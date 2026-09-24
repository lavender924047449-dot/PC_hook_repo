"""
CSV 加载器 — 把 CSV 行解析为 SendTask 列表。

约定的 CSV 格式（首行必须是表头）：

    contact,audio
    测试语音群,audios/hello.wav
    张三,audios/promo1.wav
    李四,C:\\samples\\promo2.mp3

规则：
    - `contact`     : 企微里显示的完整名称
    - `audio`       : 音频文件路径。相对路径基于 CSV 所在目录解析
    - 空行或以 # 开头的行会被跳过
    - 编码优先 UTF-8-BOM (Excel 存 CSV 默认编码)，回退 UTF-8
"""

from __future__ import annotations

import csv
from pathlib import Path

from loguru import logger

from app.orchestrator.task import SendTask


REQUIRED_COLUMNS = ("contact", "audio")


class CsvFormatError(RuntimeError):
    pass


def _open_csv(path: Path):
    """尝试 utf-8-sig → utf-8 → gbk"""
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return open(path, "r", encoding=enc, newline="")
        except UnicodeDecodeError:
            continue
    raise CsvFormatError(f"无法识别 {path} 的编码，请另存为 UTF-8")


def load_tasks(csv_path: Path | str, *, check_audio_exists: bool = True) -> list[SendTask]:
    csv_path = Path(csv_path).resolve()
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV 不存在: {csv_path}")

    tasks: list[SendTask] = []
    csv_dir = csv_path.parent

    with _open_csv(csv_path) as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise CsvFormatError("CSV 首行没有表头")
        # 归一化列名（去空格、小写）
        normalized = {c.strip().lower(): c for c in reader.fieldnames}
        missing = [c for c in REQUIRED_COLUMNS if c not in normalized]
        if missing:
            raise CsvFormatError(
                f"CSV 缺少必需列: {missing}。实际列: {list(reader.fieldnames)}"
            )
        contact_col = normalized["contact"]
        audio_col = normalized["audio"]

        for i, row in enumerate(reader, start=2):  # 2 = 表头之后第 1 行
            contact = (row.get(contact_col) or "").strip()
            audio_raw = (row.get(audio_col) or "").strip()

            # 跳过空行 / 注释
            if not contact or contact.startswith("#"):
                continue
            if not audio_raw:
                raise CsvFormatError(f"第 {i} 行: audio 为空 (contact={contact})")

            audio_path = Path(audio_raw)
            if not audio_path.is_absolute():
                audio_path = (csv_dir / audio_path).resolve()

            if check_audio_exists and not audio_path.exists():
                raise CsvFormatError(
                    f"第 {i} 行: 音频文件不存在 → {audio_path}"
                )

            tasks.append(SendTask(contact=contact, audio=audio_path, row_index=i))

    if not tasks:
        raise CsvFormatError(f"{csv_path} 没有有效任务")

    logger.info(f"从 CSV 加载 {len(tasks)} 个任务: {csv_path.name}")
    return tasks
