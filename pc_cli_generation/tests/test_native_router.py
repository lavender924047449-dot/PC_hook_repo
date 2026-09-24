"""NativeRouter 单元测试：用 fake frida + fake clock 完全隔离进程 attach。"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

import pytest

from app.pc_wecom.native_router import (
    DEFAULT_FIELD_CONV_STRING,
    DEFAULT_FIELD_PACKAGE_PTR,
    DEFAULT_VTABLE_OFFSET,
    FridaUnavailableError,
    HijackReport,
    NativeRouter,
    NotAttachedError,
    PatchResult,
    StdStringSnapshot,
    TaskSnapshot,
)


# ---------------------------------------------------------------------------
# Fake Frida 三件套
# ---------------------------------------------------------------------------


class _FakeExports:
    def __init__(
        self,
        scan_impl: Callable[[int, int, int], list[dict]],
        patch_impl: Callable[[str, str], dict],
    ) -> None:
        self._scan = scan_impl
        self._patch = patch_impl
        self.scan_calls: list[tuple[int, int, int]] = []
        self.patch_calls: list[tuple[str, str]] = []

    def scan_tasks(self, vtable_offset: int, field_package_ptr: int, field_conv_string: int) -> list[dict]:
        self.scan_calls.append((vtable_offset, field_package_ptr, field_conv_string))
        return self._scan(vtable_offset, field_package_ptr, field_conv_string)

    def patch_conv_id_heap(self, char_ptr: str, new_str: str) -> dict:
        self.patch_calls.append((char_ptr, new_str))
        return self._patch(char_ptr, new_str)


class _FakeScript:
    def __init__(
        self,
        js: str,
        exports: _FakeExports,
        auto_ready: bool = True,
        base_hex: str = "0x970000",
    ) -> None:
        self.js = js
        self.exports_sync = exports
        self._on_message: Callable[[dict, Any], None] | None = None
        self.loaded = False
        self.unloaded = False
        self.auto_ready = auto_ready
        self.base_hex = base_hex

    def on(self, event: str, cb: Callable[[dict, Any], None]) -> None:
        assert event == "message"
        self._on_message = cb

    def load(self) -> None:
        self.loaded = True
        if self.auto_ready and self._on_message is not None:
            self._on_message({"type": "send", "payload": {"t": "info", "msg": f"attached, base={self.base_hex}"}}, None)
            self._on_message({"type": "send", "payload": {"t": "ready"}}, None)

    def unload(self) -> None:
        self.unloaded = True

    def emit_ready(self) -> None:
        """手动触发 ready（用于 auto_ready=False 场景）。"""
        assert self._on_message is not None
        self._on_message({"type": "send", "payload": {"t": "ready"}}, None)

    def emit_error(self, description: str) -> None:
        assert self._on_message is not None
        self._on_message({"type": "error", "description": description}, None)


class _FakeSession:
    def __init__(self, script: _FakeScript, pid: int) -> None:
        self._script = script
        self.pid = pid
        self.detached = False
        self.create_calls: list[str] = []

    def create_script(self, js: str) -> _FakeScript:
        self.create_calls.append(js)
        self._script.js = js
        return self._script

    def detach(self) -> None:
        self.detached = True


class _FakeDevice:
    def __init__(self, script: _FakeScript) -> None:
        self._script = script
        self.attach_calls: list[int] = []

    def attach(self, pid: int) -> _FakeSession:
        self.attach_calls.append(pid)
        return _FakeSession(self._script, pid)


class _FakeFrida:
    def __init__(self, script: _FakeScript) -> None:
        self._device = _FakeDevice(script)

    def get_local_device(self) -> _FakeDevice:
        return self._device


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_task(
    *,
    task_addr: str = "0x2bd4a350",
    pkg_ptr: str = "0x34af2fd8",
    conv_size: int = 35,
    conv_str: str = "S:1688855042791155_7881300363276969",
    heap_ptr: str = "0x2b910d18",
    sso: bool = False,
) -> dict:
    return {
        "task_addr": task_addr,
        "pkg_ptr": pkg_ptr,
        "conv_string": {
            "size": conv_size,
            "cap": max(conv_size, 35),
            "sso": sso,
            "ptr": None if sso else heap_ptr,
            "str": conv_str,
            "at": "0x34af3000",
        },
        "string_obj_addr": "0x34af3000",
    }


def _fake_frida_with_scan(
    tasks_sequence: list[list[dict]],
    *,
    patch_ok: bool = True,
    patch_verify_transform: Callable[[str], str] | None = None,
    auto_ready: bool = True,
) -> tuple[_FakeFrida, _FakeScript, _FakeExports]:
    """构造一个 fake frida，其 scan_tasks 每次调用返回 tasks_sequence 中的下一批。

    最后一批之后重复返回空列表。
    """
    call_idx = {"i": 0}

    def scan_impl(*_a: Any) -> list[dict]:
        i = call_idx["i"]
        call_idx["i"] += 1
        if i < len(tasks_sequence):
            return tasks_sequence[i]
        return []

    def patch_impl(char_ptr: str, new_str: str) -> dict:
        if not patch_ok:
            return {"ok": False, "err": "simulated failure"}
        verify = patch_verify_transform(new_str) if patch_verify_transform else new_str
        return {"ok": True, "verify": verify}

    exports = _FakeExports(scan_impl, patch_impl)
    script = _FakeScript(js="", exports=exports, auto_ready=auto_ready)
    frida = _FakeFrida(script)
    return frida, script, exports


class _ControllableClock:
    def __init__(self, start: float = 0.0) -> None:
        self._now = start
        self._lock = threading.Lock()

    def now(self) -> float:
        with self._lock:
            return self._now

    def advance(self, delta: float) -> None:
        with self._lock:
            self._now += delta


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAttachDetach:
    def test_missing_frida_raises(self) -> None:
        r = NativeRouter(pid=1234, frida_module=None)
        # 显式塞 None 表示不注入且未安装
        # 但 constructor 里会 try import frida —— 如果真装了 frida，跳过
        # 所以我们直接把 _frida 设为 None
        r._frida = None  # noqa: SLF001
        with pytest.raises(FridaUnavailableError):
            r.attach()

    def test_attach_and_detach(self) -> None:
        frida, script, _ = _fake_frida_with_scan([[]])
        r = NativeRouter(pid=22184, frida_module=frida, sleep=lambda _s: None)
        r.attach()
        assert r.is_attached is True
        assert script.loaded is True
        assert r.agent_base == "0x970000"
        r.detach()
        assert r.is_attached is False
        assert script.unloaded is True

    def test_attach_uses_configured_module_name(self) -> None:
        frida, script, _ = _fake_frida_with_scan([[]])
        r = NativeRouter(pid=1, frida_module=frida, module_name="Foo.EXE",
                          sleep=lambda _s: None)
        r.attach()
        # module_name 会转小写嵌入 JS
        assert "foo.exe" in script.js.lower()
        r.detach()

    def test_context_manager(self) -> None:
        frida, script, _ = _fake_frida_with_scan([[]])
        r = NativeRouter(pid=1, frida_module=frida, sleep=lambda _s: None)
        with r as router:
            assert router.is_attached is True
        assert script.unloaded is True

    def test_attach_ready_timeout_falls_through(self) -> None:
        """script.on ready 未触发时应打警告但继续，不阻塞。"""
        frida, script, _ = _fake_frida_with_scan([[]], auto_ready=False)
        r = NativeRouter(
            pid=1,
            frida_module=frida,
            sleep=lambda _s: None,
            script_load_timeout_s=0.01,
        )
        # clock 走得比 timeout 快
        r._clock = lambda: time.monotonic() + 10.0  # noqa: SLF001
        r.attach()
        assert r.is_attached is True
        r.detach()

    def test_double_attach_is_noop(self) -> None:
        frida, script, _ = _fake_frida_with_scan([[]])
        r = NativeRouter(pid=1, frida_module=frida, sleep=lambda _s: None)
        r.attach()
        session1 = r._session  # noqa: SLF001
        r.attach()
        # 二次 attach 不重新建
        assert r._session is session1  # noqa: SLF001
        r.detach()

    def test_detach_before_attach_is_ok(self) -> None:
        r = NativeRouter(pid=1, frida_module=None)
        r._frida = None  # noqa: SLF001
        r.detach()  # 不应抛
        assert r.is_attached is False


class TestScanTasks:
    def test_scan_calls_agent_with_correct_offsets(self) -> None:
        tasks = [_make_task()]
        frida, _script, exports = _fake_frida_with_scan([tasks])
        r = NativeRouter(
            pid=1,
            frida_module=frida,
            vtable_offset=0xABBB210,
            sleep=lambda _s: None,
        )
        r.attach()
        result = r.scan_tasks()
        assert exports.scan_calls == [(0xABBB210, DEFAULT_FIELD_PACKAGE_PTR, DEFAULT_FIELD_CONV_STRING)]
        assert len(result) == 1
        snap = result[0]
        assert isinstance(snap, TaskSnapshot)
        assert snap.task_addr == "0x2bd4a350"
        assert snap.conv_string.text == "S:1688855042791155_7881300363276969"
        assert snap.conv_string.size == 35
        assert snap.conv_string.sso is False
        assert snap.conv_string.heap_ptr == "0x2b910d18"
        r.detach()

    def test_scan_snapshot_sso_mode(self) -> None:
        frida, _script, _ = _fake_frida_with_scan([[_make_task(
            conv_size=10, conv_str="FILEASSIST", sso=True, heap_ptr="",
        )]])
        r = NativeRouter(pid=1, frida_module=frida, sleep=lambda _s: None)
        r.attach()
        snaps = r.scan_tasks()
        assert snaps[0].conv_string.sso is True
        assert snaps[0].conv_string.heap_ptr in (None, "")
        r.detach()

    def test_scan_before_attach_raises(self) -> None:
        r = NativeRouter(pid=1, frida_module=None)
        r._frida = None  # noqa: SLF001
        with pytest.raises(NotAttachedError):
            r.scan_tasks()


class TestPatch:
    def test_patch_ok(self) -> None:
        frida, _script, exports = _fake_frida_with_scan([[]])
        r = NativeRouter(pid=1, frida_module=frida, sleep=lambda _s: None)
        r.attach()
        result = r.patch_conv_id("0x2b910d18", "S:1688855042791155_9999999999999999")
        assert result.ok is True
        assert result.heap_ptr == "0x2b910d18"
        assert result.verify_read == "S:1688855042791155_9999999999999999"
        assert exports.patch_calls == [("0x2b910d18", "S:1688855042791155_9999999999999999")]
        r.detach()

    def test_patch_failure(self) -> None:
        frida, _script, _ = _fake_frida_with_scan([[]], patch_ok=False)
        r = NativeRouter(pid=1, frida_module=frida, sleep=lambda _s: None)
        r.attach()
        result = r.patch_conv_id("0x2b910d18", "S:xxx")
        assert result.ok is False
        assert result.error == "simulated failure"
        r.detach()

    def test_patch_before_attach_raises(self) -> None:
        r = NativeRouter(pid=1, frida_module=None)
        r._frida = None  # noqa: SLF001
        with pytest.raises(NotAttachedError):
            r.patch_conv_id("0x1", "x")


class TestArmHijack:
    def test_length_mismatch_raises(self) -> None:
        frida, _script, _ = _fake_frida_with_scan([[]])
        r = NativeRouter(pid=1, frida_module=frida, sleep=lambda _s: None)
        r.attach()
        with pytest.raises(ValueError, match="length mismatch"):
            r.arm("S:abc", "FILEASSIST", timeout_sec=1)
        r.detach()

    def test_hijack_hits_target(self) -> None:
        """扫两次：第一次空、第二次命中原 conv_id → 应 patch 且触发 patched_event。"""
        tasks_seq = [
            [],
            [_make_task(conv_str="S:1688855042791155_7881300363276969")],
        ]
        frida, _script, exports = _fake_frida_with_scan(tasks_seq)
        r = NativeRouter(
            pid=1,
            frida_module=frida,
            scan_interval_ms=10,
            sleep=lambda _s: None,
        )
        r.attach()
        try:
            handle = r.arm(
                "S:1688855042791155_7881300363276969",
                "S:1688855042791155_7881299845935418",
                timeout_sec=2,
            )
            report = handle.wait(timeout=5)
        finally:
            r.detach()

        assert report.tasks_matched >= 1
        assert report.tasks_patched >= 1
        assert handle.wait_for_patch(timeout=0) is True
        assert len(exports.patch_calls) == 1
        assert exports.patch_calls[0] == (
            "0x2b910d18",
            "S:1688855042791155_7881299845935418",
        )
        # 事件：应至少有一个 phase=patched
        patched_events = [e for e in report.events if e["phase"] == "patched"]
        assert len(patched_events) == 1
        assert patched_events[0]["verify"] == "S:1688855042791155_7881299845935418"

    def test_hijack_ignores_non_matching_tasks(self) -> None:
        """扫到其它 conv_id 的 task 应 seen 但不 patch。"""
        tasks_seq = [
            [
                _make_task(task_addr="0xA", conv_str="FILEASSIST", conv_size=10, sso=True, heap_ptr=""),
                _make_task(task_addr="0xB", conv_str="S:1688855042791155_1111111111111111"),
            ],
        ]
        frida, _script, exports = _fake_frida_with_scan(tasks_seq)
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=10, sleep=lambda _s: None)
        r.attach()
        try:
            handle = r.arm(
                "S:1688855042791155_7881300363276969",
                "S:1688855042791155_7881299845935418",
                timeout_sec=0.2,
            )
            report = handle.wait(timeout=5)
        finally:
            r.detach()
        assert report.tasks_matched == 0
        assert report.tasks_patched == 0
        assert report.tasks_seen_unique == 2
        assert exports.patch_calls == []

    def test_hijack_sso_matching_cannot_patch(self) -> None:
        """匹配到 conv_id 但 SSO 模式无 heap_ptr → 应记录 matched_no_heap_ptr。"""
        # 让 conv_id 严格匹配 && sso=True && heap_ptr=None
        tasks_seq = [[
            _make_task(
                conv_str="short_id",
                conv_size=8,
                sso=True,
                heap_ptr="",
            ),
        ]]
        frida, _script, exports = _fake_frida_with_scan(tasks_seq)
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=10, sleep=lambda _s: None)
        r.attach()
        try:
            handle = r.arm("short_id", "SHORT_ID", timeout_sec=0.2)
            report = handle.wait(timeout=5)
        finally:
            r.detach()
        assert report.tasks_matched == 1
        assert report.tasks_patched == 0
        assert any(e["phase"] == "matched_no_heap_ptr" for e in report.events)
        assert exports.patch_calls == []

    def test_hijack_patch_failure(self) -> None:
        tasks_seq = [[_make_task(conv_str="S:1688855042791155_7881300363276969")]]
        frida, _script, exports = _fake_frida_with_scan(tasks_seq, patch_ok=False)
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=10, sleep=lambda _s: None)
        r.attach()
        try:
            handle = r.arm(
                "S:1688855042791155_7881300363276969",
                "S:1688855042791155_7881299845935418",
                timeout_sec=0.2,
            )
            report = handle.wait(timeout=5)
        finally:
            r.detach()
        assert report.tasks_matched == 1
        assert report.tasks_patched == 0
        assert any(e["phase"] == "matched_patch_failed" for e in report.events)
        assert len(exports.patch_calls) == 1

    def test_hijack_timeout(self) -> None:
        """始终扫不到 → 到 timeout_sec 自然结束，timed_out=True。"""
        frida, _script, _ = _fake_frida_with_scan([[]])  # 后续所有 scan 都返回空
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=10, sleep=lambda _s: None)
        r.attach()
        try:
            handle = r.arm("A" * 20, "B" * 20, timeout_sec=0.15)
            report = handle.wait(timeout=5)
        finally:
            r.detach()
        assert report.timed_out is True
        assert report.stopped is False
        assert report.tasks_patched == 0

    def test_hijack_max_patches(self) -> None:
        """max_patches=2 命中两次后应停止。"""
        # 5 次扫描全都命中新的 task
        tasks_seq = [
            [_make_task(task_addr=f"0x{i:x}", conv_str="S:1688855042791155_7881300363276969")]
            for i in range(5)
        ]
        frida, _script, exports = _fake_frida_with_scan(tasks_seq)
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=10, sleep=lambda _s: None)
        r.attach()
        try:
            handle = r.arm(
                "S:1688855042791155_7881300363276969",
                "S:1688855042791155_7881299845935418",
                timeout_sec=5,
                max_patches=2,
            )
            report = handle.wait(timeout=5)
        finally:
            r.detach()
        assert report.tasks_patched == 2
        assert report.timed_out is False
        assert len(exports.patch_calls) == 2

    def test_hijack_stop(self) -> None:
        """外部 stop() 应尽快结束循环。"""
        frida, _script, _ = _fake_frida_with_scan([[]])
        # sleep 用真 sleep 让 stop 能中断
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=20, sleep=time.sleep)
        r.attach()
        try:
            handle = r.arm("X" * 20, "Y" * 20, timeout_sec=10)
            time.sleep(0.05)
            report = handle.stop(timeout=2)
        finally:
            r.detach()
        assert report.stopped is True
        assert report.timed_out is False
        assert handle.is_done() is True

    def test_hijack_dedups_same_task_addr(self) -> None:
        """同一个 task_addr 出现多次只算 seen 一次。"""
        task = _make_task(conv_str="S:xxx", conv_size=5)
        # 前面命中，第二次同一 task 又出现
        tasks_seq = [[task], [task], [task]]
        frida, _script, exports = _fake_frida_with_scan(tasks_seq)
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=10, sleep=lambda _s: None)
        r.attach()
        try:
            handle = r.arm("nomatch1", "nomatch2", timeout_sec=0.2)
            report = handle.wait(timeout=5)
        finally:
            r.detach()
        assert report.tasks_seen_unique == 1
        assert report.tasks_matched == 0

    def test_hijack_scan_exception_records_error(self) -> None:
        """scan_tasks 抛异常时应记录 error 并结束。"""
        def scan_impl(*_a: Any) -> list[dict]:
            raise RuntimeError("boom")

        exports = _FakeExports(scan_impl, lambda *_a: {"ok": True, "verify": ""})
        script = _FakeScript(js="", exports=exports, auto_ready=True)
        frida = _FakeFrida(script)
        r = NativeRouter(pid=1, frida_module=frida, scan_interval_ms=10, sleep=lambda _s: None)
        r.attach()
        try:
            handle = r.arm("A" * 5, "B" * 5, timeout_sec=1)
            report = handle.wait(timeout=5)
        finally:
            r.detach()
        assert report.error is not None
        assert "boom" in report.error


class TestReportDict:
    def test_report_to_dict_roundtrips(self) -> None:
        rep = HijackReport(
            from_conv_id="A" * 5,
            to_conv_id="B" * 5,
            scans_done=3,
            tasks_seen_unique=2,
            tasks_matched=1,
            tasks_patched=1,
            duration_sec=1.234,
            timed_out=False,
            events=[{"phase": "patched"}],
        )
        d = rep.to_dict()
        assert d["from_conv_id"] == "AAAAA"
        assert d["tasks_patched"] == 1
        assert d["duration_sec"] == 1.234
        assert d["events"] == [{"phase": "patched"}]

    def test_std_string_snapshot_from_js_dict(self) -> None:
        snap = StdStringSnapshot.from_js_dict(
            {"size": 10, "cap": 15, "sso": True, "str": "hi"},
            string_obj_addr="0xff",
        )
        assert snap.size == 10
        assert snap.sso is True
        assert snap.heap_ptr is None
        assert snap.text == "hi"
        assert snap.string_obj_addr == "0xff"

    def test_patch_result_defaults(self) -> None:
        r = PatchResult(ok=False, heap_ptr="0x1")
        assert r.error is None
        assert r.verify_read is None
