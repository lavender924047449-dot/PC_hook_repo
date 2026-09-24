"""内存扫描读取企微消息三元组 (message_id, sequence, send_time)。

原理：WXWork.exe 将消息记录缓存在内存中，每条记录含
  [message_id: u64][sequence: u64][send_time_ms: u64]
使用 Windows ReadProcessMemory 扫描 (sequence, send_time_ms) 对，
再向前 8 字节读取 message_id 候选值。

支持平台：Windows x86/x64（目标进程 WXWork.exe 32-bit）
依赖：仅 ctypes（标准库）
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

__all__ = [
    "MessageTriplet",
    "find_wxwork_pid",
    "scan_message_triplets",
    "find_triplet_by_send_time",
    "WeComMemoryReader",
]

# ─── 常量 ──────────────────────────────────────────────────────────────────────

_PROCESS_VM_READ = 0x0010
_PROCESS_QUERY_INFORMATION = 0x0400
_MEM_COMMIT = 0x1000

# 可读/写的内存保护标志
_READABLE_PROTECTS = {0x02, 0x04, 0x20, 0x24, 0x40, 0x44, 0x80}

# send_time 高 32 位范围（毫秒时间戳）
# 2020-01-01 000ms → 0x16 * 2^32 ≈ 0x16_0000_0000
# 2030-01-01 000ms → 0x1B * 2^32 ≈ 0x1B_C0_0000_0000
_MIN_ST_HI = 0x16C  # 约 2020 ms高位
_MAX_ST_HI = 0x1B0  # 约 2030 ms高位

# 合法 sequence 范围（企微消息序列号）
_MIN_SEQ = 1
_MAX_SEQ = 10_000_000

# 合法 Unix 秒时间戳范围
_MIN_TS_S = 1_577_836_800  # 2020-01-01
_MAX_TS_S = 1_893_456_000  # 2030-01-01

# 每次读取块大小
_CHUNK = 4 * 1024 * 1024  # 4 MB

# 单次扫描最大内存量（防止占用过高）
# WXWork.exe 32-bit 的目标数据区在 ~600MB 虚拟地址，需要较大范围
_MAX_SCAN_MB = 1024


# ─── 数据结构 ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MessageTriplet:
    """从进程内存中读取的消息三元组。"""

    memory_addr: int      # 内存中 sequence 字段的地址
    message_id: int       # 企微 message_id（u64，可能为 rowid 或内部 ID）
    sequence: int         # 会话内消息序列号（u64）
    send_time_ms: int     # 发送时间（Unix 毫秒时间戳，u64）

    @property
    def send_time_s(self) -> int:
        """发送时间（Unix 秒时间戳）。"""
        return self.send_time_ms // 1000

    @property
    def send_time_dt(self) -> datetime:
        """发送时间（UTC datetime）。"""
        return datetime.fromtimestamp(self.send_time_s, tz=timezone.utc)

    def to_dict(self) -> dict:
        return {
            "memory_addr": hex(self.memory_addr),
            "message_id": self.message_id,
            "sequence": self.sequence,
            "send_time_ms": self.send_time_ms,
            "send_time_s": self.send_time_s,
            "send_time_dt": self.send_time_dt.isoformat(),
        }


# ─── Windows 结构 ──────────────────────────────────────────────────────────────


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]


# ─── 核心读取 ─────────────────────────────────────────────────────────────────


def _read_memory(h_proc, addr: int, size: int) -> bytes | None:
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(
        h_proc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)
    )
    return buf.raw[: n.value] if ok and n.value > 0 else None


def _iter_readable_regions(h_proc) -> Iterator[tuple[int, int]]:
    """枚举进程所有可读内存区域，yield (base, size)。"""
    mbi = _MEMORY_BASIC_INFORMATION()
    cursor = 0x10000
    scanned_mb = 0

    while cursor < 0x7FFF_0000:
        ret = ctypes.windll.kernel32.VirtualQueryEx(
            h_proc, ctypes.c_void_p(cursor), ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if ret == 0:
            break
        region_size = mbi.RegionSize
        if (
            mbi.State == _MEM_COMMIT
            and mbi.Protect in _READABLE_PROTECTS
            and 0 < region_size <= 64 * 1024 * 1024
        ):
            yield cursor, region_size
            scanned_mb += region_size // (1024 * 1024)
            if scanned_mb > _MAX_SCAN_MB:
                break

        next_cursor = cursor + max(region_size, 0x1000)
        if next_cursor <= cursor:
            break
        cursor = next_cursor


def _scan_region_for_pairs(
    raw: bytes,
    base_addr: int,
    results: list[MessageTriplet],
    max_results: int,
) -> None:
    """在 raw 字节中扫描 (sequence, send_time_ms) 对并读取 message_id。"""
    data_len = len(raw)
    # 需要 16 字节前缀（message_id）+ 16 字节（seq + ts）= 32 字节
    for i in range(0, data_len - 32, 4):
        seq_lo, seq_hi = struct.unpack_from("<II", raw, i)
        if seq_hi != 0:
            continue
        if not (_MIN_SEQ <= seq_lo <= _MAX_SEQ):
            continue

        st_lo, st_hi = struct.unpack_from("<II", raw, i + 8)
        if not (_MIN_ST_HI <= st_hi <= _MAX_ST_HI):
            continue

        ts_ms = (st_hi << 32) | st_lo
        ts_s = ts_ms // 1000
        if not (_MIN_TS_S <= ts_s <= _MAX_TS_S):
            continue

        # 向前 8 字节读取 message_id 候选
        if i >= 8:
            mid_lo, mid_hi = struct.unpack_from("<II", raw, i - 8)
            message_id = (mid_hi << 32) | mid_lo
        else:
            message_id = 0

        addr = base_addr + i
        results.append(
            MessageTriplet(
                memory_addr=addr,
                message_id=message_id,
                sequence=seq_lo,
                send_time_ms=ts_ms,
            )
        )
        if len(results) >= max_results:
            return


# ─── 公开接口 ─────────────────────────────────────────────────────────────────


def find_wxwork_pid() -> int | None:
    """找到内存最大的 WXWork.exe PID。

    Returns:
        PID，失败返回 None。
    """
    try:
        import csv
        import io
        import subprocess

        output = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"],
            text=True,
            encoding="gbk",
            errors="replace",
        )
        best_pid, best_mem = None, 0
        reader = csv.reader(io.StringIO(output.strip()))
        for row in reader:
            if len(row) >= 5:
                try:
                    pid = int(row[1])
                    mem_kb = int(row[4].replace(",", "").replace(" K", "").strip())
                    if mem_kb > best_mem:
                        best_mem, best_pid = mem_kb, pid
                except ValueError:
                    pass
        return best_pid
    except Exception:
        return None


def scan_message_triplets(
    pid: int,
    *,
    max_results: int = 200,
    max_candidates: int = 10_000,
    min_ts_s: int = _MIN_TS_S,
    max_ts_s: int = _MAX_TS_S,
) -> list[MessageTriplet]:
    """扫描进程内存，返回所有合法的消息三元组。

    Args:
        pid:           目标进程 PID（WXWork.exe 主进程）。
        max_results:   最多返回多少条（时间过滤后）结果。
        max_candidates: 扫描时最多读取多少候选对（早停条件，防止无限扫描）。
        min_ts_s / max_ts_s: 时间戳过滤范围（Unix 秒）。

    Returns:
        MessageTriplet 列表，按 send_time_ms 升序排列。
    """
    h_proc = ctypes.windll.kernel32.OpenProcess(
        _PROCESS_VM_READ | _PROCESS_QUERY_INFORMATION, False, pid
    )
    if not h_proc:
        raise PermissionError(f"无法打开进程 PID={pid}，错误码 {ctypes.GetLastError()}")

    candidates: list[MessageTriplet] = []
    try:
        for base, size in _iter_readable_regions(h_proc):
            chunk_cursor = base
            while chunk_cursor < base + size and len(candidates) < max_candidates:
                read_size = min(_CHUNK, base + size - chunk_cursor)
                raw = _read_memory(h_proc, chunk_cursor, read_size)
                if raw and len(raw) >= 32:
                    _scan_region_for_pairs(raw, chunk_cursor, candidates, max_candidates)
                chunk_cursor += read_size
            if len(candidates) >= max_candidates:
                break
    finally:
        ctypes.windll.kernel32.CloseHandle(h_proc)

    # 时间范围精过滤
    results = [
        t
        for t in candidates
        if min_ts_s <= t.send_time_s <= max_ts_s
    ]
    results.sort(key=lambda t: t.send_time_ms)
    return results[:max_results]


def find_triplet_by_send_time(
    pid: int,
    send_time_ms: int,
    *,
    tolerance_ms: int = 10_000,
) -> MessageTriplet | None:
    """查找与指定发送时间最近的消息三元组。

    Args:
        pid: WXWork.exe 主进程 PID。
        send_time_ms: 目标发送时间（Unix 毫秒）。
        tolerance_ms: 允许偏差毫秒数（默认 10 秒）。

    Returns:
        最接近的 MessageTriplet，或 None（未找到）。
    """
    min_ts = (send_time_ms - tolerance_ms) // 1000
    max_ts = (send_time_ms + tolerance_ms) // 1000

    triplets = scan_message_triplets(
        pid,
        max_results=500,
        max_candidates=10_000,
        min_ts_s=max(min_ts, _MIN_TS_S),
        max_ts_s=min(max_ts, _MAX_TS_S),
    )
    if not triplets:
        return None

    best = min(triplets, key=lambda t: abs(t.send_time_ms - send_time_ms))
    if abs(best.send_time_ms - send_time_ms) <= tolerance_ms:
        return best
    return None


# ─── 便捷类封装 ──────────────────────────────────────────────────────────────


class WeComMemoryReader:
    """企微内存读取器，封装进程 PID 管理。

    v2 新增：增量扫描缓存（_hit_regions）。
    首次全量扫描约 17–23s；命中区域缓存后，后续扫描仅扫已知区域，约 1–3s。

    Usage::

        reader = WeComMemoryReader()
        triplets = reader.scan_recent(minutes=30)
        t = reader.find_by_send_time(send_time_ms=1788959471492)
    """

    # 增量扫描时每个命中区域对齐的块大小（4 MB，与全量扫描的 _CHUNK 一致）
    _REGION_BLOCK = 4 * 1024 * 1024
    _MAX_CACHED_REGIONS = 32  # 最多缓存的命中区域数量

    def __init__(self, pid: int | None = None) -> None:
        if pid is None:
            pid = find_wxwork_pid()
        if pid is None:
            raise RuntimeError("未找到 WXWork.exe 进程，请确认企微已启动")
        self.pid = pid
        # 已知命中的内存区域 (base_addr, size)，用于增量扫描加速
        self._hit_regions: list[tuple[int, int]] = []

    # ── 增量扫描辅助 ───────────────────────────────────────────────────────────

    def _cache_hit_regions(self, triplets: list[MessageTriplet]) -> None:
        """将命中三元组所在的 4MB 块加入 _hit_regions 缓存。"""
        for t in triplets:
            base = (t.memory_addr // self._REGION_BLOCK) * self._REGION_BLOCK
            entry = (base, self._REGION_BLOCK)
            if entry not in self._hit_regions:
                self._hit_regions.append(entry)
        # 只保留最近 N 个区域，防止无限增长
        self._hit_regions = self._hit_regions[-self._MAX_CACHED_REGIONS :]

    def _scan_in_hit_regions(
        self,
        min_ts_s: int,
        max_ts_s: int,
    ) -> list[MessageTriplet]:
        """仅扫描缓存的命中区域（快速路径，约 1–3s）。"""
        if not self._hit_regions:
            return []
        h_proc = ctypes.windll.kernel32.OpenProcess(
            _PROCESS_VM_READ | _PROCESS_QUERY_INFORMATION, False, self.pid
        )
        if not h_proc:
            return []
        candidates: list[MessageTriplet] = []
        try:
            for base, size in self._hit_regions:
                chunk_cursor = base
                while chunk_cursor < base + size:
                    read_size = min(_CHUNK, base + size - chunk_cursor)
                    raw = _read_memory(h_proc, chunk_cursor, read_size)
                    if raw and len(raw) >= 32:
                        _scan_region_for_pairs(raw, chunk_cursor, candidates, 10_000)
                    chunk_cursor += read_size
        finally:
            ctypes.windll.kernel32.CloseHandle(h_proc)
        return [t for t in candidates if min_ts_s <= t.send_time_s <= max_ts_s]

    # ── 公开接口 ───────────────────────────────────────────────────────────────

    def scan_recent(
        self,
        *,
        minutes: int = 60,
        max_results: int = 200,
    ) -> list[MessageTriplet]:
        """扫描最近 N 分钟内的消息三元组，并更新命中区域缓存。"""
        now = int(time.time())
        triplets = scan_message_triplets(
            self.pid,
            max_results=max_results,
            max_candidates=10_000,
            min_ts_s=now - minutes * 60,
            max_ts_s=now + 3600,
        )
        if triplets:
            self._cache_hit_regions(triplets)
        return triplets

    def find_by_send_time(
        self,
        send_time_ms: int,
        *,
        tolerance_ms: int = 10_000,
    ) -> MessageTriplet | None:
        """按发送时间（毫秒）查找对应三元组。

        优先扫描缓存的命中区域（快，约 1–3s）；未命中再做全量扫描（约 17–23s）。
        """
        min_ts = max((send_time_ms - tolerance_ms) // 1000, _MIN_TS_S)
        max_ts = min((send_time_ms + tolerance_ms) // 1000, _MAX_TS_S)

        # ── 快速路径：仅扫已知命中区域 ──────────────────────────────────────
        if self._hit_regions:
            candidates = self._scan_in_hit_regions(min_ts, max_ts)
            if candidates:
                best = min(candidates, key=lambda t: abs(t.send_time_ms - send_time_ms))
                if abs(best.send_time_ms - send_time_ms) <= tolerance_ms:
                    logger.debug(
                        f"[内存扫描 快速路径] 命中 regions={len(self._hit_regions)} "
                        f"ts_ms={best.send_time_ms}"
                    )
                    self._cache_hit_regions([best])
                    return best
            logger.debug(
                f"[内存扫描 快速路径] 未命中，降级全量扫描 "
                f"(cached_regions={len(self._hit_regions)})"
            )

        # ── 全量扫描（慢路径）────────────────────────────────────────────────
        result = find_triplet_by_send_time(self.pid, send_time_ms, tolerance_ms=tolerance_ms)
        if result:
            self._cache_hit_regions([result])
            logger.debug(
                f"[内存扫描 全量] 命中 ts_ms={result.send_time_ms} "
                f"→ 已缓存 {len(self._hit_regions)} 个区域"
            )
        return result

    def scan_all(self, *, max_results: int = 200) -> list[MessageTriplet]:
        """扫描全部历史消息三元组（较慢，约 17–23s），并更新命中区域缓存。"""
        triplets = scan_message_triplets(
            self.pid,
            max_results=max_results,
            max_candidates=10_000,
        )
        if triplets:
            self._cache_hit_regions(triplets)
        return triplets

    def clear_region_cache(self) -> None:
        """清空命中区域缓存（企微重启或版本更新后调用）。"""
        self._hit_regions.clear()
        logger.debug("[内存扫描] 已清空命中区域缓存")
