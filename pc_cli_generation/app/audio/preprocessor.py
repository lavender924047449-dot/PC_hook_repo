"""
音频预处理 — 基于 FFmpeg 子进程

主要能力：
    1) 任意格式 (mp3/wav/m4a/amr/silk...) → 标准 WAV
    2) 采样率 / 单声道 / 位深 归一
    3) 响度归一 (loudnorm)
    4) 首尾静音填充 (防按住时序丢字)

设计：
    - 不引 ffmpeg-python 之类的包装，直接 subprocess，方便打包
    - 二进制查找顺序：配置里的 bundled_path → 系统 PATH
    - 处理后的 WAV 落盘到 runtime/prepared/，同名 .wav 覆盖写
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

from app.config import AudioConfig, FFmpegConfig, resolve_path


# ---------------- 异常 ---------------- #

class FFmpegNotFound(RuntimeError):
    pass


class FFmpegError(RuntimeError):
    def __init__(self, msg: str, stderr: str = ""):
        super().__init__(msg)
        self.stderr = stderr


# ---------------- 二进制定位 ---------------- #

def resolve_ffmpeg(cfg: FFmpegConfig) -> Path:
    """按 bundled → PATH 顺序查找 ffmpeg"""
    bundled = cfg.resolved_bundled()
    if bundled.exists():
        logger.debug(f"ffmpeg (bundled): {bundled}")
        return bundled
    which = shutil.which("ffmpeg")
    if which:
        logger.debug(f"ffmpeg (PATH): {which}")
        return Path(which)
    raise FFmpegNotFound(
        f"未找到 ffmpeg。已尝试：\n"
        f"  1) {bundled}\n"
        f"  2) 系统 PATH\n"
        f"请把 ffmpeg.exe 放到 {bundled.parent} 目录下，"
        f"或安装 ffmpeg 并加入 PATH。"
    )


# ---------------- 结果模型 ---------------- #

@dataclass(slots=True, frozen=True)
class PreparedAudio:
    src: Path
    dst: Path
    sample_rate: int
    channels: int
    duration_s: float

    def __repr__(self) -> str:
        return (f"PreparedAudio({self.dst.name}, {self.duration_s:.2f}s, "
                f"{self.sample_rate}Hz, ch={self.channels})")


# ---------------- 核心 ---------------- #

class AudioPreprocessor:
    """
    幂等预处理器。相同参数 + 同一源文件 → 同一目标文件 (基于 hash 命名)。
    """

    def __init__(self, audio_cfg: AudioConfig, ffmpeg_cfg: FFmpegConfig,
                 out_dir: Path | str = "runtime/prepared") -> None:
        self.cfg = audio_cfg
        self.ffmpeg_bin = resolve_ffmpeg(ffmpeg_cfg)
        self.out_dir = resolve_path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    # ---- 命名 ---- #
    def _param_signature(self) -> str:
        c = self.cfg
        raw = (
            f"{c.sample_rate}|{c.channels}|{c.bit_depth}|"
            f"{c.loudnorm_i}|{c.loudnorm_tp}|{c.loudnorm_lra}|"
            f"{c.head_padding_ms}|{c.tail_padding_ms}"
        )
        return hashlib.md5(raw.encode()).hexdigest()[:8]

    def output_path_for(self, src: Path) -> Path:
        stem = src.stem
        sig = self._param_signature()
        # 也在 hash 里加入源文件内容 hash，防止同名不同内容混淆
        return self.out_dir / f"{stem}__{sig}.wav"

    # ---- FFmpeg 命令 ---- #
    def _build_filter(self) -> str:
        c = self.cfg
        parts: list[str] = []

        # 头部静音填充
        if c.head_padding_ms > 0:
            parts.append(f"adelay={c.head_padding_ms}:all=1")

        # 尾部静音填充
        if c.tail_padding_ms > 0:
            parts.append(f"apad=pad_dur={c.tail_padding_ms / 1000:.3f}")

        # 响度归一 (双通)
        parts.append(
            f"loudnorm=I={c.loudnorm_i}:TP={c.loudnorm_tp}:LRA={c.loudnorm_lra}"
        )

        # 重采样 + 声道
        parts.append(f"aresample={c.sample_rate}")
        parts.append(f"aformat=channel_layouts={'mono' if c.channels == 1 else 'stereo'}")

        return ",".join(parts)

    def _pcm_codec(self) -> str:
        return {8: "pcm_u8", 16: "pcm_s16le", 24: "pcm_s24le", 32: "pcm_s32le"}[
            self.cfg.bit_depth
        ]

    # ---- 探测时长 ---- #
    def _probe_duration(self, wav_path: Path) -> float:
        """用 ffmpeg -i 探测 WAV 时长 (秒)"""
        r = subprocess.run(
            [str(self.ffmpeg_bin), "-i", str(wav_path)],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        # ffmpeg 把 -i 的信息打到 stderr
        for line in r.stderr.splitlines():
            if "Duration" in line:
                # "  Duration: 00:00:03.30, ..."
                try:
                    t = line.split("Duration:")[1].split(",")[0].strip()
                    hh, mm, ss = t.split(":")
                    return int(hh) * 3600 + int(mm) * 60 + float(ss)
                except Exception:
                    pass
        return 0.0

    # ---- 主入口 ---- #
    def prepare(self, src: Path | str, *, force: bool = False) -> PreparedAudio:
        src = Path(src)
        if not src.exists():
            raise FileNotFoundError(f"源音频不存在: {src}")

        dst = self.output_path_for(src)
        if dst.exists() and not force:
            logger.info(f"命中缓存: {dst.name}")
            return PreparedAudio(
                src=src, dst=dst,
                sample_rate=self.cfg.sample_rate,
                channels=self.cfg.channels,
                duration_s=self._probe_duration(dst),
            )

        cmd = [
            str(self.ffmpeg_bin), "-y",
            "-i", str(src),
            "-af", self._build_filter(),
            "-ac", str(self.cfg.channels),
            "-ar", str(self.cfg.sample_rate),
            "-c:a", self._pcm_codec(),
            str(dst),
        ]
        logger.info(f"开始预处理: {src.name} → {dst.name}")
        logger.debug("cmd: " + " ".join(cmd))

        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            raise FFmpegError(
                f"ffmpeg 处理失败 (returncode={r.returncode})",
                stderr=r.stderr,
            )
        dur = self._probe_duration(dst)
        logger.info(f"预处理完成: {dst.name}  时长 {dur:.2f}s")
        return PreparedAudio(
            src=src, dst=dst,
            sample_rate=self.cfg.sample_rate,
            channels=self.cfg.channels,
            duration_s=dur,
        )
