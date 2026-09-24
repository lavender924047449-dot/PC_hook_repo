"""
AndroidFileStore — 把本地文件推到 Android 设备并复用 (Stage 4.5.3).

设计:
    - push 到 /sdcard/Pictures/wecom_batch/ (可配), 触发 MediaScanner
    - 用 (size, mtime, name) 组合做缓存 key, 同文件不重复 push
    - 相册/文件浏览器随时可选中
    - 会话结束可调 cleanup() 清理
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path

import adbutils
from loguru import logger


DEFAULT_REMOTE_DIR = "/sdcard/Pictures/wecom_batch"


@dataclass
class PushedFile:
    local: Path
    remote: str            # Android 端绝对路径
    size: int              # 字节


class AndroidFileStore:
    """
    幂等的文件推送 + MediaScanner 扫描.

    典型用法:
        store = AndroidFileStore(sess.adb)
        remote = store.ensure(Path("C:/pics/a.jpg"))
        # 之后可以在相册里通过文件名找到
    """

    def __init__(
        self,
        adb: adbutils.AdbDevice,
        remote_dir: str = DEFAULT_REMOTE_DIR,
    ) -> None:
        self.adb = adb
        self.remote_dir = remote_dir.rstrip("/")
        self._pushed: dict[str, PushedFile] = {}
        self._dir_ensured = False

    # ---------------- 公共 API ---------------- #

    def ensure(self, local: Path | str) -> str:
        """
        确保 local 已在设备上, 返回 Android 端绝对路径.
        同一 local 文件 (按 size+mtime+name 判定) 只 push 一次.
        """
        local = Path(local).resolve()
        if not local.is_file():
            raise FileNotFoundError(f"本地文件不存在: {local}")

        st = local.stat()
        key = f"{st.st_size}_{int(st.st_mtime)}_{local.name}"
        if key in self._pushed:
            logger.debug(f"[file_store] 命中缓存: {local.name}")
            return self._pushed[key].remote

        self._ensure_dir()
        # 用文件名 (若重名会覆盖旧的; 因为 key 里含 size+mtime, 同名不同内容
        # 会得到不同 key, 但 remote 名相同会覆盖. 为稳妥起见, 加短哈希前缀)
        safe_name = _safe_remote_name(local, st.st_mtime, st.st_size)
        remote = posixpath.join(self.remote_dir, safe_name)

        logger.info(
            f"[file_store] push {local} → {remote}  "
            f"({st.st_size:,} bytes)"
        )
        self.adb.push(str(local), remote)
        self._media_scan(remote)

        rec = PushedFile(local=local, remote=remote, size=st.st_size)
        self._pushed[key] = rec
        return remote

    def cleanup(self) -> None:
        """删除本会话推过去的所有文件"""
        if not self._pushed:
            return
        logger.info(f"[file_store] cleanup {len(self._pushed)} files")
        for rec in self._pushed.values():
            try:
                self.adb.shell(f'rm -f "{rec.remote}"')
                self._media_scan(rec.remote)
            except Exception as e:
                logger.debug(f"cleanup {rec.remote} 失败: {e}")
        self._pushed.clear()

    def all_remotes(self) -> list[str]:
        return [r.remote for r in self._pushed.values()]

    # ---------------- 内部 ---------------- #

    def _ensure_dir(self) -> None:
        if self._dir_ensured:
            return
        self.adb.shell(f'mkdir -p "{self.remote_dir}"')
        self._dir_ensured = True

    def _media_scan(self, remote_path: str) -> None:
        """通知 Android MediaStore 重扫这个文件, 相册/文件管理器立刻可见"""
        # 单文件扫描更精确
        cmd = (
            "am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE "
            f'-d "file://{remote_path}"'
        )
        try:
            self.adb.shell(cmd)
        except Exception as e:
            logger.debug(f"media scan 失败 (可忽略): {e}")


# ---------- helpers ---------- #

def _safe_remote_name(local: Path, mtime: float, size: int) -> str:
    """
    给 remote 文件加一个短哈希前缀, 避免同名不同内容互相覆盖.
    保留原扩展名, 相册按 MIME 分类不会乱.
    """
    import hashlib

    h = hashlib.md5(f"{local.name}_{mtime}_{size}".encode()).hexdigest()[:6]
    stem = local.stem
    suffix = local.suffix
    return f"wb_{h}_{stem}{suffix}"
