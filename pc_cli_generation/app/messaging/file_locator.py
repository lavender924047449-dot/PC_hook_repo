"""把 FTA 消息里的文件名/大小解析成本地路径。

只在「缓存目录没有新文件」时使用：
- 第一次发送：仍优先 Cache/File 落盘；
- 转发已有文件：用消息里的文件名去 Cache/File 和素材库里对路径。

不扫描整个磁盘，避免把回写拖慢到秒级以上。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.messaging.asset_library import AssetLibrary
from app.messaging.types import MessageType

_COPY_SUFFIX_RE = re.compile(r"(?:\s*\(\d+\))+$")

FILE_SUFFIXES: frozenset[str] = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".txt", ".csv", ".mp3", ".wav",
    ".apk", ".exe", ".png", ".jpg", ".jpeg", ".gif", ".mp4",
    ".wps", ".et", ".dps", ".ofd", ".rtf", ".json", ".xml",
    ".pptm", ".xlsm", ".dotx", ".ppsx",
})

_NAME_RE = re.compile(
    r"([\w\u4e00-\u9fff][\w\u4e00-\u9fff().\s\-—_]{0,180}\.(?:pdf|docx?|xlsx?|pptx?|zip|rar|7z|txt|csv|mp3|wav|apk|exe|png|jpe?g|gif|mp4|wps|et|dps|ofd|rtf|json|xml|pptm|xlsm|dotx|ppsx))",
    re.I,
)
_SIZE_RE = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|字节|千字节|兆)\s*$",
    re.I,
)


@dataclass(frozen=True)
class FileHint:
    filename: str
    size: int | None = None


def parse_size_label(text: str) -> int | None:
    raw = (text or "").strip().replace("，", ".")
    m = _SIZE_RE.match(raw)
    if m is None:
        return None
    n = float(m.group(1))
    unit = m.group(2).lower()
    if unit in {"b", "字节"}:
        return int(n)
    if unit in {"kb", "千字节"}:
        return int(n * 1024)
    if unit in {"mb", "兆"}:
        return int(n * 1024 * 1024)
    if unit == "gb":
        return int(n * 1024 * 1024 * 1024)
    return None


def parse_file_hints(texts: list[str]) -> list[FileHint]:
    """从聊天气泡可见文本里抽出文件名；紧随其后的体积文案会绑到上一个文件。"""
    hints: list[FileHint] = []
    for raw in texts:
        text = (raw or "").strip()
        if not text:
            continue
        size = parse_size_label(text)
        names = [m.group(1).strip() for m in _NAME_RE.finditer(text)]
        if names:
            for name in names:
                hints.append(FileHint(filename=name, size=None))
            continue
        if size is not None and hints:
            last = hints[-1]
            if last.size is None:
                hints[-1] = FileHint(filename=last.filename, size=size)
    return _dedupe_keep_last(hints)


def _dedupe_keep_last(hints: list[FileHint]) -> list[FileHint]:
    by_name: dict[str, FileHint] = {}
    order: list[str] = []
    for h in hints:
        key = h.filename.lower()
        if key not in by_name:
            order.append(key)
        by_name[key] = h
    return [by_name[k] for k in order]


def _name_match(path: Path, filename: str, stem: str, suffix: str) -> bool:
    if path.name.lower() == filename.lower():
        return True
    if path.suffix.lower() != suffix:
        return False
    return _COPY_SUFFIX_RE.sub("", path.stem).strip().lower() == stem.lower()


def _size_close(actual: int, expected: int) -> bool:
    tol = max(2048, int(expected * 0.05))
    return abs(actual - expected) <= tol


def _iter_cache_files(cache_root: Path) -> list[Path]:
    root = Path(cache_root) / "File"
    if not root.is_dir():
        return []
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        if any(part == "Temp" for part in rel.parts):
            continue
        out.append(p)
    return out


def resolve_local_file(
    cache_root: Path,
    hint: FileHint,
    *,
    library: AssetLibrary | None = None,
) -> Path | None:
    """Cache/File 优先，其次素材库里已登记的本地路径。不扫全盘。"""
    filename = Path(hint.filename).name.strip()
    if not filename:
        return None
    suffix = Path(filename).suffix.lower()
    if suffix not in FILE_SUFFIXES:
        return None
    stem = _COPY_SUFFIX_RE.sub("", Path(filename).stem).strip() or Path(filename).stem

    candidates: list[Path] = []
    seen: set[str] = set()

    def _add(path: Path) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            return
        key = str(resolved).lower()
        if key in seen or not resolved.is_file():
            return
        seen.add(key)
        candidates.append(resolved)

    for p in _iter_cache_files(cache_root):
        if _name_match(p, filename, stem, suffix):
            _add(p)

    if library is not None:
        for entry in library.by_type(MessageType.FILE):
            src = (entry.source_path or "").strip()
            if src:
                p = Path(src)
                if _name_match(p, filename, stem, suffix):
                    _add(p)
            display = (entry.display_name or "").strip()
            if display and _COPY_SUFFIX_RE.sub("", display).strip().lower() == stem.lower() and src:
                _add(Path(src))

    if not candidates:
        return None

    if hint.size is not None:
        sized = []
        for p in candidates:
            try:
                if _size_close(p.stat().st_size, hint.size):
                    sized.append(p)
            except OSError:
                continue
        if sized:
            candidates = sized

    exact = [p for p in candidates if p.name.lower() == filename.lower()]
    pool = exact or candidates
    return max(pool, key=lambda p: p.stat().st_size)


__all__ = [
    "FileHint",
    "FILE_SUFFIXES",
    "parse_file_hints",
    "parse_size_label",
    "resolve_local_file",
]
