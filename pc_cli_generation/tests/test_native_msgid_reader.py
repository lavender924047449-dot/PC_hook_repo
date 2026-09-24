"""NativeMsgIdReader 单元测试（不依赖 Frida / 企微进程）。"""
from __future__ import annotations

import json
import time
from pathlib import Path

from app.pc_wecom.native_msgid_reader import NativeMsgIdReader, NativeMsgIdRecord


def _write_map(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def test_missing_file_returns_empty(tmp_path):
    r = NativeMsgIdReader(tmp_path / "nope.json")
    assert r.snapshot() == {}
    assert r.get_by_send_time(123) is None
    assert r.get_by_msgid(1) is None


def test_load_and_lookup_by_send_time_exact(tmp_path):
    p = tmp_path / "map.json"
    _write_map(p, {
        "1789137936": {"msgid": 461, "send_time_ms": 1789137936,
                       "conversation_id": None, "sql": "..."},
    })
    r = NativeMsgIdReader(p)
    hit = r.get_by_send_time(1789137936)
    assert isinstance(hit, NativeMsgIdRecord)
    assert hit.msgid == 461
    assert hit.send_time_ms == 1789137936


def test_lookup_within_tolerance(tmp_path):
    p = tmp_path / "map.json"
    _write_map(p, {
        "1789137936": {"msgid": 461, "send_time_ms": 1789137936},
    })
    r = NativeMsgIdReader(p)
    # ±1000 ms 内应命中
    assert r.get_by_send_time(1789137935, tolerance_ms=1000).msgid == 461
    # 超出容差应 miss
    assert r.get_by_send_time(1789137000, tolerance_ms=100) is None


def test_lookup_by_msgid(tmp_path):
    p = tmp_path / "map.json"
    _write_map(p, {
        "1789137936": {"msgid": 461, "send_time_ms": 1789137936},
        "1789137999": {"msgid": 462, "send_time_ms": 1789137999},
    })
    r = NativeMsgIdReader(p)
    assert r.get_by_msgid(461).send_time_ms == 1789137936
    assert r.get_by_msgid(462).send_time_ms == 1789137999
    assert r.get_by_msgid(999) is None


def test_hot_reload_on_mtime_change(tmp_path):
    p = tmp_path / "map.json"
    _write_map(p, {})
    r = NativeMsgIdReader(p, poll_interval_s=0.01)
    assert r.get_by_msgid(461) is None
    # 模拟后台 hook 进程写入新数据
    time.sleep(0.02)  # 保证 mtime_ns 不同
    _write_map(p, {"1789137936": {"msgid": 461, "send_time_ms": 1789137936}})
    hit = r.get_by_msgid(461)
    assert hit is not None
    assert hit.send_time_ms == 1789137936


def test_wait_for_msgid_returns_immediately_when_present(tmp_path):
    p = tmp_path / "map.json"
    _write_map(p, {"1789137936": {"msgid": 461, "send_time_ms": 1789137936}})
    r = NativeMsgIdReader(p, poll_interval_s=0.05)
    t0 = time.monotonic()
    hit = r.wait_for_msgid(1789137936, timeout=1.0)
    assert hit is not None and hit.msgid == 461
    assert time.monotonic() - t0 < 0.5  # 立即返回，不等 timeout


def test_wait_for_msgid_times_out(tmp_path):
    p = tmp_path / "map.json"
    _write_map(p, {})
    r = NativeMsgIdReader(p, poll_interval_s=0.02)
    t0 = time.monotonic()
    assert r.wait_for_msgid(1789137936, timeout=0.1) is None
    assert 0.1 <= time.monotonic() - t0 < 0.5


def test_wait_for_msgid_picks_up_late_write(tmp_path):
    """后台 hook 进程在 wait 期间写入新数据，应能被轮询到。"""
    import threading
    p = tmp_path / "map.json"
    _write_map(p, {})
    r = NativeMsgIdReader(p, poll_interval_s=0.02)

    def _late_write():
        time.sleep(0.15)
        _write_map(p, {"1789137936": {"msgid": 461, "send_time_ms": 1789137936}})

    threading.Thread(target=_late_write, daemon=True).start()
    hit = r.wait_for_msgid(1789137936, timeout=2.0)
    assert hit is not None
    assert hit.msgid == 461
