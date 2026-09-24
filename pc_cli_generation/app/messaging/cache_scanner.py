"""
WeCom 缓存扫描器（升级版）。

能力：
- `watchdog` 事件驱动，尽量近实时捕捉新增素材；
- 保留轮询兜底（默认 2 秒）防止漏事件；
- 输出统一事件 `MaterialCaptured`，供编码回写/锚点模块订阅。
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, ClassVar, Iterable

from loguru import logger

from app.messaging.asset_library import AssetEntry, AssetLibrary
from app.messaging.types import MessageType

_WATCHDOG_IMPORT_ERROR: BaseException | None = None
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except Exception as e:  # pragma: no cover - watchdog 可选依赖
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None  # type: ignore[assignment]
    _WATCHDOG_IMPORT_ERROR = e

CACHE_SUBDIR_TO_TYPE: dict[str, MessageType] = {
    "File": MessageType.FILE,
    "Image": MessageType.IMAGE,
    "Video": MessageType.VIDEO,
    "Voice": MessageType.VOICE,
}

# 默认扫描 Cache 下全部四类：Image / Video / File / Voice。
SKIP_BY_DEFAULT: frozenset[str] = frozenset()

# 企微对同一张图常写入两份缓存：原文件 + `文件名(1).png` 转码副本，字节不同所以哈希不同。
# 去掉末尾连续的 `(数字)` 后视为同一次发送。
_COPY_SUFFIX_RE = re.compile(r"(?:\s*\(\d+\))+$")
# 企微发视频时会先在 Image/ 落下 UUID 文件名的封面缩略图。
_VIDEO_THUMB_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
# 视频封面处理时间窗口（加大以应对大文件落盘慢的情况）
_VIDEO_THUMB_HOLD_S = 5.0   # 封面等待时间：给视频文件更多落盘时间


def logical_cache_stem(stem: str) -> str:
    return _COPY_SUFFIX_RE.sub("", stem).strip() or stem


FileStat = tuple[int, float] | tuple[int, float, float]


@dataclass(frozen=True)
class CachedFile:
    path: Path
    semantic_type: MessageType
    subdir: str
    mtime: float
    size: int
    atime: float = 0.0


@dataclass(frozen=True)
class MaterialCaptured:
    entry: AssetEntry
    source_file: Path
    captured_at: str


@dataclass
class ScanResult:
    new_files: list[CachedFile]
    registered: list[AssetEntry]
    skipped_by_type: dict[str, int]


def looks_like_video_thumb(cf: CachedFile) -> bool:
    if cf.semantic_type is not MessageType.IMAGE:
        return False
    if cf.path.suffix.lower() not in {".jpg", ".jpeg", ".png"}:
        return False
    if cf.size > 80_000:
        return False
    return _VIDEO_THUMB_RE.fullmatch(cf.path.stem) is not None


class _FsEventHandler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, on_file: Callable[[Path], None]) -> None:
        self._on_file = on_file
        super().__init__()

    def on_created(self, event) -> None:  # pragma: no cover - 由集成测试覆盖
        if getattr(event, "is_directory", False):
            return
        self._on_file(Path(event.src_path))

    def on_moved(self, event) -> None:  # pragma: no cover - 由集成测试覆盖
        if getattr(event, "is_directory", False):
            return
        self._on_file(Path(event.dest_path))


class WeComCacheScanner:
    DEFAULT_WXWORK_ROOT: ClassVar[Path] = Path.home() / "Documents" / "WXWork"
    _IGNORE_SUBDIRS: ClassVar[frozenset[str]] = frozenset({"Temp"})
    _MIN_FILE_SIZE: ClassVar[int] = 100
    _OBSERVER_START_TIMEOUT_S: ClassVar[float] = 3.0

    def __init__(
        self,
        account_dir: Path,
        *,
        skip_subdirs: Iterable[str] | None = None,
        dedup_window_s: float = 5.0,
        poll_fallback_s: float = 0.4,
        silk_decoder: object | None = None,
    ) -> None:
        self.account_dir = Path(account_dir)
        self.cache_root = self.account_dir / "Cache"
        if not self.account_dir.is_dir():
            raise NotADirectoryError(f"账号目录不存在: {self.account_dir}")
        if not self.cache_root.is_dir():
            raise NotADirectoryError(f"Cache 目录不存在: {self.cache_root}")

        if skip_subdirs is None:
            skip_subdirs = SKIP_BY_DEFAULT
        self.skip_subdirs = frozenset(skip_subdirs)
        self.dedup_window_s = float(dedup_window_s)
        self.poll_fallback_s = float(poll_fallback_s)
        self.silk_decoder = silk_decoder
        self._event_subscribers: list[Callable[[MaterialCaptured], None]] = []
        self._recent_paths: dict[str, float] = {}
        self._pending: dict[str, CachedFile] = {}
        self._pending_paths: dict[str, set[Path]] = {}
        self._pending_touch: dict[str, float] = {}
        self._last_video_flush_at: float = 0.0
        self._last_video_entry: AssetEntry | None = None

    @classmethod
    def list_accounts(cls, wxwork_root: Path | None = None) -> list[tuple[str, int]]:
        root = wxwork_root or cls.DEFAULT_WXWORK_ROOT
        if not root.is_dir():
            return []
        out: list[tuple[str, int]] = []
        for sub in root.iterdir():
            if not sub.is_dir() or not sub.name.isdigit() or len(sub.name) < 10:
                continue
            cache = sub / "Cache"
            if not cache.is_dir():
                out.append((sub.name, 0))
                continue
            out.append((sub.name, sum(1 for p in cache.rglob("*") if p.is_file())))
        out.sort(key=lambda x: -x[1])
        return out

    @classmethod
    def auto_detect(
        cls,
        wxwork_root: Path | None = None,
        *,
        skip_subdirs: Iterable[str] | None = None,
        dedup_window_s: float = 5.0,
        poll_fallback_s: float = 0.4,
        silk_decoder: object | None = None,
    ) -> WeComCacheScanner:
        accts = cls.list_accounts(wxwork_root)
        if not accts:
            root = wxwork_root or cls.DEFAULT_WXWORK_ROOT
            raise FileNotFoundError(f"未在 {root} 下发现企微账号目录")
        best_id, best_n = accts[0]
        if best_n == 0:
            raise FileNotFoundError("发现账号目录但缓存都是空的")
        root = wxwork_root or cls.DEFAULT_WXWORK_ROOT
        return cls(
            root / best_id,
            skip_subdirs=skip_subdirs,
            dedup_window_s=dedup_window_s,
            poll_fallback_s=poll_fallback_s,
            silk_decoder=silk_decoder,
        )

    def subscribe(self, callback: Callable[[MaterialCaptured], None]) -> None:
        self._event_subscribers.append(callback)

    def snapshot(self) -> list[CachedFile]:
        out: list[CachedFile] = []
        for subdir_name, msg_type in CACHE_SUBDIR_TO_TYPE.items():
            d = self.cache_root / subdir_name
            if not d.is_dir():
                continue
            for f in d.rglob("*"):
                if not f.is_file():
                    continue
                rel = f.relative_to(d)
                if any(p.name in self._IGNORE_SUBDIRS for p in rel.parents):
                    continue
                try:
                    st = f.stat()
                except OSError:
                    continue
                if st.st_size < self._MIN_FILE_SIZE:
                    continue
                out.append(
                    CachedFile(
                        path=f,
                        semantic_type=msg_type,
                        subdir=subdir_name,
                        mtime=st.st_mtime,
                        size=st.st_size,
                        atime=st.st_atime,
                    )
                )
        out.sort(key=lambda x: (x.subdir, x.path.name))
        return out

    def snapshot_paths(self) -> set[Path]:
        return {f.path for f in self.snapshot()}

    def snapshot_stat(self) -> dict[Path, tuple[int, float, float]]:
        return {f.path: (f.size, f.mtime, f.atime) for f in self.snapshot()}

    @staticmethod
    def _live_stat(path: Path, cf: CachedFile | None = None) -> tuple[int, float, float]:
        try:
            st = path.stat()
            return (st.st_size, st.st_mtime, st.st_atime)
        except OSError:
            if cf is None:
                return (0, 0.0, 0.0)
            return (cf.size, cf.mtime, cf.atime)

    def bind_video_covers(self, lib: AssetLibrary) -> None:
        """用磁盘上已有的「封面 jpg + 数秒内 mp4」给视频条目补封面指纹。"""
        snap = self.snapshot()
        covers = [c for c in snap if looks_like_video_thumb(c)]
        videos = [c for c in snap if c.semantic_type is MessageType.VIDEO]
        if not covers or not videos:
            return
        by_path = {
            Path(e.source_path).resolve(): e
            for e in lib.by_type(MessageType.VIDEO)
            if e.source_path
        }
        linked = 0
        for cover in covers:
            cands = [v for v in videos if 0 <= (v.mtime - cover.mtime) <= 10.0]
            if not cands:
                continue
            v = min(cands, key=lambda x: x.mtime - cover.mtime)
            entry = by_path.get(v.path.resolve())
            if entry is None:
                continue
            fp = self._file_fingerprint(cover.path)
            if not fp:
                continue
            if self._remember_cover(entry, fp):
                linked += 1
        if linked:
            logger.info(f"已绑定 {linked} 个视频封面指纹，便于同一视频再次发送时回写 vid 编码")

    @staticmethod
    def _file_fingerprint(path: Path) -> str | None:
        try:
            h = hashlib.sha1()
            with path.open("rb") as f:
                while True:
                    b = f.read(65536)
                    if not b:
                        break
                    h.update(b)
            return h.hexdigest()
        except OSError:
            return None

    @staticmethod
    def _remember_cover(entry: AssetEntry, fp: str) -> bool:
        fps = list(entry.cover_fingerprints or [])
        if fp in fps:
            return False
        fps.append(fp)
        entry.cover_fingerprints = fps
        return True

    def _lookup_video_by_cover(self, lib: AssetLibrary, fp: str) -> AssetEntry | None:
        for e in lib.by_type(MessageType.VIDEO):
            if fp in (e.cover_fingerprints or []):
                return e
        return None

    def register_new(
        self,
        lib: AssetLibrary,
        *,
        baseline_paths: set[Path] | None = None,
        baseline_stat: dict[Path, FileStat] | None = None,
        since_ts: float | None = None,
        source_account: str | None = None,
        coalesce_quiet_s: float = 0.0,
    ) -> ScanResult:
        current = self.snapshot()
        new_files: list[CachedFile] = []
        for cf in current:
            if since_ts is not None and cf.mtime <= since_ts:
                continue
            if baseline_paths is not None and cf.path in baseline_paths:
                prev = None if baseline_stat is None else baseline_stat.get(cf.path)
                if prev is None:
                    continue
                same_bytes = prev[0] == cf.size and prev[1] == cf.mtime
                if same_bytes:
                    continue
            new_files.append(cf)

        skipped: dict[str, int] = {}
        skipped_files: list[CachedFile] = []
        for cf in new_files:
            if cf.subdir in self.skip_subdirs:
                skipped[cf.subdir] = skipped.get(cf.subdir, 0) + 1
                skipped_files.append(cf)
                continue
            self._note_pending(cf)

        flushed = self._flush_pending(
            lib,
            source_account=source_account,
            quiet_s=coalesce_quiet_s,
        )
        for k, v in skipped.items():
            flushed.skipped_by_type[k] = flushed.skipped_by_type.get(k, 0) + v
        return ScanResult(
            new_files=skipped_files + flushed.new_files,
            registered=flushed.registered,
            skipped_by_type=flushed.skipped_by_type,
        )

    def _group_key(self, cf: CachedFile) -> str:
        return f"{cf.subdir}:{logical_cache_stem(cf.path.stem)}"

    def _note_pending(self, cf: CachedFile) -> None:
        key = self._group_key(cf)
        known = self._pending_paths.setdefault(key, set())
        is_new_path = cf.path not in known
        known.add(cf.path)
        old = self._pending.get(key)
        if old is None or cf.size > old.size:
            self._pending[key] = cf
        elif old is not None and cf.size == old.size and str(cf.path) < str(old.path):
            self._pending[key] = cf
        # 只有真正新出现的副本才重置等待；轮询再次扫到已见文件时不得清零，
        # 否则 quiet 窗口会被永远推迟，编码迟迟不回写。
        if is_new_path:
            self._pending_touch[key] = time.monotonic()

    def _flush_pending(
        self,
        lib: AssetLibrary,
        *,
        source_account: str | None,
        quiet_s: float,
    ) -> ScanResult:
        now = time.monotonic()
        # 视频文件需要更长的等待时间（大文件落盘慢）
        video_quiet_s = max(quiet_s, 2.5)
        if quiet_s <= 0:
            ready_keys = list(self._pending)
        else:
            ready_keys = []
            for k, ts in self._pending_touch.items():
                cf = self._pending.get(k)
                if cf is None:
                    continue
                n_copies = len(self._pending_paths.get(k, ()))
                # 视频封面：等待 _VIDEO_THUMB_HOLD_S 后再处理
                if looks_like_video_thumb(cf):
                    if now - ts >= max(quiet_s, _VIDEO_THUMB_HOLD_S):
                        ready_keys.append(k)
                    continue
                # 视频文件：等待更长时间，确保大文件落盘完成
                if cf.semantic_type is MessageType.VIDEO:
                    if n_copies >= 2 or now - ts >= video_quiet_s:
                        ready_keys.append(k)
                    continue
                # 其他类型：普通逻辑
                if n_copies >= 2 or now - ts >= quiet_s:
                    ready_keys.append(k)

        flushing_video = any(
            (hit := self._pending.get(k)) is not None and hit.semantic_type is MessageType.VIDEO
            for k in ready_keys
        )

        # 先处理视频，再处理封面，才能把封面指纹绑到 vid 编码上。
        def _flush_order(k: str) -> int:
            cf = self._pending.get(k)
            if cf is None:
                return 2
            if cf.semantic_type is MessageType.VIDEO:
                return 0
            if looks_like_video_thumb(cf):
                return 1
            return 2

        all_new: list[CachedFile] = []
        registered: list[AssetEntry] = []
        skipped: dict[str, int] = {}
        for key in sorted(ready_keys, key=_flush_order):
            winner = self._pending.pop(key, None)
            paths = self._pending_paths.pop(key, set())
            self._pending_touch.pop(key, None)
            if winner is None:
                continue
            siblings = [winner]
            for p in paths:
                if p == winner.path:
                    continue
                extra = self._to_cached_file(p)
                if extra is not None:
                    siblings.append(extra)
            all_new.extend(siblings)
            extras = len(siblings) - 1
            if extras > 0:
                skipped["wecom_copy"] = skipped.get("wecom_copy", 0) + extras
                logger.info(
                    f"企微同一次发送产生 {len(siblings)} 份缓存，只保留最大文件: {winner.path.name}"
                )
            if looks_like_video_thumb(winner):
                cover_fp = self._file_fingerprint(winner.path)
                video_entry = None
                # 同一轮刚入库的 mp4：封面属于这次发送，不是猜「最近一条视频」。
                if flushing_video and self._last_video_entry is not None:
                    video_entry = self._last_video_entry
                if video_entry is None and cover_fp:
                    video_entry = self._lookup_video_by_cover(lib, cover_fp)
                if video_entry is not None:
                    if cover_fp:
                        self._remember_cover(video_entry, cover_fp)
                    skipped["video_cover"] = skipped.get("video_cover", 0) + 1
                    logger.info(
                        f"视频封面映射到 {video_entry.material_code}（不生成 img 编码）: {winner.path.name}"
                    )
                    self._emit_captured(video_entry, winner.path)
                    if not any(e.tag == video_entry.tag for e in registered):
                        registered.append(video_entry)
                    continue
                skipped["video_cover"] = skipped.get("video_cover", 0) + 1
                logger.info(
                    f"视频封面未匹配到已有 vid，本地 Cache/Video 也无新文件: {winner.path.name}"
                )
                continue
            entry = self._register_cached(lib, winner, source_account)
            if entry is not None:
                registered.append(entry)
                if winner.semantic_type is MessageType.VIDEO:
                    self._last_video_flush_at = now
                    self._last_video_entry = entry
                    logger.debug(
                        f"视频处理完成 {entry.material_code}，同轮封面将按指纹绑定"
                    )
        return ScanResult(new_files=all_new, registered=registered, skipped_by_type=skipped)

    def _register_cached(
        self,
        lib: AssetLibrary,
        cf: CachedFile,
        source_account: str | None,
    ) -> AssetEntry | None:
        try:
            source_path = cf.path
            if (
                cf.semantic_type is MessageType.VOICE
                and self.silk_decoder is not None
                and cf.path.suffix.lower() == ".silk"
                and hasattr(self.silk_decoder, "decode_to_cache")
            ):
                source_path = self.silk_decoder.decode_to_cache(cf.path)  # type: ignore[assignment]
            entry = lib.register_local(
                source_path,
                cf.semantic_type,
                display_name=logical_cache_stem(cf.path.stem) or cf.path.stem,
                source_account=source_account or self.account_dir.name,
            )
            self._emit_captured(entry, cf.path)
            return entry
        except Exception as e:
            logger.warning(f"入库失败 {cf.path}: {e}")
            return None

    def watch_and_register(
        self,
        lib: AssetLibrary,
        *,
        timeout_s: float = 0.0,
        poll_interval_s: float = 1.5,
        stop_on_first_batch: bool = False,
    ) -> ScanResult:
        baseline_stat = self.snapshot_stat()
        seen_paths = set(baseline_stat)
        deadline = None if timeout_s <= 0 else time.perf_counter() + timeout_s
        all_new: list[CachedFile] = []
        all_registered: list[AssetEntry] = []
        all_skipped: dict[str, int] = {}

        while deadline is None or time.perf_counter() < deadline:
            res = self.register_new(
                lib,
                baseline_paths=seen_paths,
                baseline_stat=baseline_stat,
            )
            if res.new_files:
                all_new.extend(res.new_files)
                all_registered.extend(res.registered)
                for k, v in res.skipped_by_type.items():
                    all_skipped[k] = all_skipped.get(k, 0) + v
                for cf in res.new_files:
                    seen_paths.add(cf.path)
                    baseline_stat[cf.path] = self._live_stat(cf.path, cf)
                if stop_on_first_batch:
                    break
            time.sleep(poll_interval_s)
        return ScanResult(new_files=all_new, registered=all_registered, skipped_by_type=all_skipped)

    def watch_stream(
        self,
        lib: AssetLibrary,
        *,
        timeout_s: float = 0.0,
        source_account: str | None = None,
    ) -> ScanResult:
        """
        常驻监听（`timeout_s<=0` 表示无限）。返回收集到的统计结果。
        """
        baseline_stat = self.snapshot_stat()
        seen = set(baseline_stat)
        deadline = time.perf_counter() + timeout_s if timeout_s > 0 else None
        self.bind_video_covers(lib)

        observer = None
        if Observer is not None:
            observer = self._start_observer(lib, source_account)
        else:
            err = f"（{_WATCHDOG_IMPORT_ERROR}）" if _WATCHDOG_IMPORT_ERROR else ""
            logger.warning(f"watchdog 不可用{err}，自动退化为轮询模式")

        all_new: list[CachedFile] = []
        all_registered: list[AssetEntry] = []
        all_skipped: dict[str, int] = {}
        try:
            while True:
                if deadline is not None and time.perf_counter() >= deadline:
                    break
                res = self.register_new(
                    lib,
                    baseline_paths=seen,
                    baseline_stat=baseline_stat,
                    source_account=source_account or self.account_dir.name,
                    coalesce_quiet_s=max(0.35, self.poll_fallback_s),
                )
                if res.new_files:
                    for cf in res.new_files:
                        seen.add(cf.path)
                        baseline_stat[cf.path] = self._live_stat(cf.path, cf)
                    all_new.extend(res.new_files)
                    all_registered.extend(res.registered)
                    for k, v in res.skipped_by_type.items():
                        all_skipped[k] = all_skipped.get(k, 0) + v
                    if res.registered:
                        try:
                            lib.save()
                        except Exception as e:
                            logger.warning(f"素材库即时保存失败: {e}")
                time.sleep(self.poll_fallback_s)
            leftover = self.register_new(
                lib,
                baseline_paths=seen,
                baseline_stat=baseline_stat,
                source_account=source_account or self.account_dir.name,
                coalesce_quiet_s=0.0,
            )
            if leftover.new_files:
                for cf in leftover.new_files:
                    seen.add(cf.path)
                    baseline_stat[cf.path] = self._live_stat(cf.path, cf)
                all_new.extend(leftover.new_files)
                all_registered.extend(leftover.registered)
                for k, v in leftover.skipped_by_type.items():
                    all_skipped[k] = all_skipped.get(k, 0) + v
        finally:
            if observer is not None:
                observer.stop()
                observer.join(timeout=2.0)

        return ScanResult(new_files=all_new, registered=all_registered, skipped_by_type=all_skipped)

    def _start_observer(
        self,
        lib: AssetLibrary,
        source_account: str | None,
    ):
        """启动 watchdog；若被上一次残留进程卡住，超时后改轮询，避免主线程假死。"""
        assert Observer is not None
        candidate = Observer()
        candidate.daemon = True
        handler = _FsEventHandler(lambda p: self._handle_fs_event(p, lib, source_account))
        candidate.schedule(handler, str(self.cache_root), recursive=True)
        started = threading.Event()

        def _start() -> None:
            candidate.start()
            started.set()

        boot = threading.Thread(target=_start, daemon=True, name="watchdog-start")
        boot.start()
        boot.join(self._OBSERVER_START_TIMEOUT_S)
        if not started.is_set():
            logger.warning(
                "文件系统监听启动超时，改为轮询。"
                "通常是已有另一个 scan-cache 占用目录：请结束旧 python 进程后再开。"
            )
            return None
        return candidate

    def _handle_fs_event(
        self,
        path: Path,
        lib: AssetLibrary,
        source_account: str | None,
    ) -> None:
        path = Path(path)
        if not path.exists() or not path.is_file():
            return
        cf = self._to_cached_file(path)
        if cf is None or cf.subdir in self.skip_subdirs:
            return
        if self._is_recent_duplicate(path):
            return
        self._note_pending(cf)

    def _to_cached_file(self, path: Path) -> CachedFile | None:
        try:
            rel = path.relative_to(self.cache_root)
        except ValueError:
            return None
        parts = rel.parts
        if len(parts) < 2:
            return None
        subdir = parts[0]
        msg_type = CACHE_SUBDIR_TO_TYPE.get(subdir)
        if msg_type is None:
            return None
        if any(x in self._IGNORE_SUBDIRS for x in parts):
            return None
        try:
            st = path.stat()
        except OSError:
            return None
        if st.st_size < self._MIN_FILE_SIZE:
            return None
        return CachedFile(
            path=path,
            semantic_type=msg_type,
            subdir=subdir,
            mtime=st.st_mtime,
            size=st.st_size,
            atime=st.st_atime,
        )

    def _is_recent_duplicate(self, path: Path) -> bool:
        now = time.time()
        key = str(path.resolve())
        last = self._recent_paths.get(key)
        self._recent_paths[key] = now
        if last is None:
            return False
        return (now - last) <= self.dedup_window_s


    def _emit_captured(self, entry: AssetEntry, source_file: Path) -> None:
        evt = MaterialCaptured(
            entry=entry,
            source_file=source_file,
            captured_at=datetime.now().isoformat(timespec="seconds"),
        )
        for sub in self._event_subscribers:
            try:
                sub(evt)
            except Exception as e:
                logger.warning(f"MaterialCaptured 订阅者异常: {e}")


__all__ = [
    "WeComCacheScanner",
    "CachedFile",
    "MaterialCaptured",
    "ScanResult",
    "CACHE_SUBDIR_TO_TYPE",
    "SKIP_BY_DEFAULT",
    "logical_cache_stem",
    "looks_like_video_thumb",
]
