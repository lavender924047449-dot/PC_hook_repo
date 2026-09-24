"""基于 SQLite bind hook 的 msgid 读取器（app 侧轻量消费端）。

数据来源：`runtime/wecom_re/hook_sqlite_bind.py` 后台 Frida 进程写出的
`runtime/wecom_re/native_msgid_map.json`，结构为
`{ str(send_time_ms): { msgid, send_time_ms, conversation_id,
                        con_numeric_id, appinfo_hex, sql, ts } }`

本模块只做：
* 按 `send_time_ms` 主键查（容差匹配）
* 按 `msgid` 反查
* 轮询文件更新（默认 200ms），支持阻塞等待

这样把 Frida hook（重）和业务读取（轻）解耦，业务侧无需 attach 企微进程。

用法：
    reader = NativeMsgIdReader(
        Path("runtime/wecom_re/native_msgid_map.json"),
    )
    hit = reader.wait_for_msgid(
        send_time_ms=1789137936,
        tolerance_ms=2000,
        timeout=8.0,
    )
    # → NativeMsgIdRecord(msgid=461, send_time_ms=1789137936, ...) or None
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class NativeMsgIdRecord:
    """由 SQLite bind hook 落地的一条 msgid 记录。"""

    msgid: int
    send_time_ms: int
    conversation_id: Optional[str] = None
    con_numeric_id: Optional[int] = None
    appinfo_hex: Optional[str] = None
    sql: Optional[str] = None
    ts: Optional[int] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NativeMsgIdRecord":
        return cls(
            msgid=int(d.get("msgid", 0)),
            send_time_ms=int(d.get("send_time_ms", 0)),
            conversation_id=d.get("conversation_id"),
            con_numeric_id=d.get("con_numeric_id"),
            appinfo_hex=d.get("appinfo_hex"),
            sql=d.get("sql"),
            ts=d.get("ts"),
        )


class NativeMsgIdReader:
    """轮询式 msgid 读取器。

    Args:
        map_path:    `native_msgid_map.json` 的路径。
        poll_interval_s: 轮询文件 mtime 的间隔（秒）。
    """

    def __init__(
        self,
        map_path: Path,
        *,
        poll_interval_s: float = 0.2,
    ) -> None:
        self._map_path = Path(map_path)
        self._poll_interval_s = float(poll_interval_s)
        self._cache_mtime_ns: int = -1
        self._by_send_time: dict[int, NativeMsgIdRecord] = {}
        self._by_msgid: dict[int, NativeMsgIdRecord] = {}
        self._load_if_changed()

    # ── 内部 ─────────────────────────────────────────────────────────────
    def _load_if_changed(self) -> bool:
        """若 map 文件 mtime 变化则重新加载；返回是否刷新。"""
        try:
            st = self._map_path.stat()
        except FileNotFoundError:
            return False
        if st.st_mtime_ns == self._cache_mtime_ns:
            return False
        try:
            raw = json.loads(self._map_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        by_time: dict[int, NativeMsgIdRecord] = {}
        by_mid: dict[int, NativeMsgIdRecord] = {}
        for k, v in raw.items():
            if not isinstance(v, dict):
                continue
            try:
                rec = NativeMsgIdRecord.from_dict(v)
            except (TypeError, ValueError):
                continue
            if rec.send_time_ms:
                by_time[rec.send_time_ms] = rec
            if rec.msgid:
                by_mid[rec.msgid] = rec
        self._by_send_time = by_time
        self._by_msgid = by_mid
        self._cache_mtime_ns = st.st_mtime_ns
        return True

    def _find_by_send_time(
        self, target: int, tolerance_ms: int
    ) -> Optional[NativeMsgIdRecord]:
        if target in self._by_send_time:
            return self._by_send_time[target]
        best: Optional[NativeMsgIdRecord] = None
        best_delta: Optional[int] = None
        for st, rec in self._by_send_time.items():
            d = abs(st - target)
            if d <= tolerance_ms and (best_delta is None or d < best_delta):
                best, best_delta = rec, d
        return best

    # ── 公开接口 ─────────────────────────────────────────────────────────
    def get_by_send_time(
        self,
        send_time_ms: int,
        *,
        tolerance_ms: int = 2000,
    ) -> Optional[NativeMsgIdRecord]:
        """立即（不阻塞）按 send_time_ms 查一次。"""
        self._load_if_changed()
        return self._find_by_send_time(int(send_time_ms), int(tolerance_ms))

    def get_by_msgid(self, msgid: int) -> Optional[NativeMsgIdRecord]:
        """立即（不阻塞）按 msgid 反查。"""
        self._load_if_changed()
        return self._by_msgid.get(int(msgid))

    def wait_for_msgid(
        self,
        send_time_ms: int,
        *,
        tolerance_ms: int = 2000,
        timeout: float = 15.0,
    ) -> Optional[NativeMsgIdRecord]:
        """阻塞轮询，直到命中一条 send_time_ms 邻近记录或超时。

        Returns:
            命中的 NativeMsgIdRecord；超时返回 None。
        """
        target = int(send_time_ms)
        tol = int(tolerance_ms)
        deadline = time.monotonic() + float(timeout)
        while True:
            self._load_if_changed()
            hit = self._find_by_send_time(target, tol)
            if hit is not None:
                return hit
            if time.monotonic() >= deadline:
                return None
            time.sleep(self._poll_interval_s)

    def snapshot(self) -> dict[int, NativeMsgIdRecord]:
        """返回当前全部 msgid 索引（send_time_ms → record 的副本）。"""
        self._load_if_changed()
        return dict(self._by_send_time)
