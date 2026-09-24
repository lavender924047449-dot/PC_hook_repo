"""基于 Frida 只读扫堆 + heap 数据覆写的 conv_id 重定向路由器。

设计目标
--------
在企微 5.0.10.6015 (32-bit) 上，通过 native hijack 把消息路由从"UI 选中的联系人"
重定向到"我们指定的目标 conv_id"，从而绕过 UIA 长按/搜人/选人的脆弱步骤。

关键技术栈（第二十五轮实证，见 `docs/REVERSE_ENGINEERING_HANDOFF.md` §41）:

* Frida read-only ``attach`` —— 只 attach 不 hook，**完全不触发企微 anti-tamper**
* ``Process.enumerateRanges({protection: 'rw-'})`` + ``Memory.scanSync`` 扫堆
* 通过 ``PostSendMessageTask2`` vtable (``wxwork.exe + 0xabbb210``) 定位活着的 Task 对象
* ``task+0x30 -> package_ptr -> package+0x28 = std::string(conversationId)``
* ``NativePointer.writeByteArray`` 覆写 heap 上的字符串数据 (不动 size/cap/ptr 元信息)
* 长度必须相同 (通常 35 == ``S:{16}_{16}``)

安全约束
--------
* 禁止 ``Interceptor.attach`` / ``Interceptor.replace`` (第二十四轮实证会导致企微退出)
* 禁止写 ``.text`` 代码段
* 只写 heap 数据段是安全的 (第二十五轮实证)

依赖注入
--------
``NativeRouter`` 通过 ``frida_module`` 参数接受 Frida 模块 (默认 ``frida``)。
测试中传入 fake frida 可完全隔离进程 attach。
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# 企微 5.0.10.6015 (32-bit) 常量 —— 若企微升版需重新逆向确认
DEFAULT_VTABLE_OFFSET = 0xABBB210  # PostSendMessageTask2 vtable @ wxwork.exe + offset
DEFAULT_FIELD_PACKAGE_PTR = 0x30  # task->[0x30] = package_ptr
DEFAULT_FIELD_CONV_STRING = 0x28  # package->[0x28] = std::string conversationId
DEFAULT_MODULE_NAME = "wxwork.exe"

DEFAULT_SCAN_INTERVAL_MS = 150
DEFAULT_TIMEOUT_SEC = 30


# ---------------------------------------------------------------------------
# Frida agent JS
# ---------------------------------------------------------------------------

# 模板变量：{MODULE_NAME}
_FRIDA_JS_TEMPLATE = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === '{MODULE_NAME}';
})[0];
if (!wx) throw new Error('module not loaded: {MODULE_NAME}');
const WXBASE = wx.base;
send({t:'info', msg: 'attached, base=' + WXBASE});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }

function bytesToAscii(bytes, size){
    let s = '';
    for (let i = 0; i < size && i < bytes.length; i++){
        const b = bytes[i];
        s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
    }
    return s;
}

function readStdString(base){
    const size = u32(base.add(0x10));
    const cap  = u32(base.add(0x14));
    if (size === 0) return {size:0, cap:cap, str:''};
    if (size <= 15){
        let bytes;
        try { bytes = new Uint8Array(base.readByteArray(16)); }
        catch(e){ return {size:size, cap:cap, err:'read sso failed'}; }
        return {size:size, cap:cap, sso:true, str:bytesToAscii(bytes, size),
                at: base.toString()};
    }
    const ptrU32 = u32(base);
    if (!ptrU32) return {size:size, cap:cap, err:'null ptr'};
    let bytes;
    try { bytes = new Uint8Array(ptr(ptrU32).readByteArray(size)); }
    catch(e){ return {size:size, cap:cap, err:'heap read failed'}; }
    return {size:size, cap:cap, sso:false, ptr:'0x'+ptrU32.toString(16),
            str: bytesToAscii(bytes, size), at: base.toString()};
}

rpc.exports = {
    scanTasks: function(vtableOffsetInt, fieldPackagePtr, fieldConvString){
        const vtVA = WXBASE.add(vtableOffsetInt).toUInt32();
        const vtBytes = [
            (vtVA & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 8) & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 16) & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 24) & 0xff).toString(16).padStart(2, '0')
        ].join(' ');
        const results = [];
        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: false});
        for (let i = 0; i < ranges.length; i++){
            const r = ranges[i];
            try {
                const ms = Memory.scanSync(r.base, r.size, vtBytes);
                for (let j = 0; j < ms.length; j++){
                    const taskAddr = ms[j].address;
                    const pkgPtr = u32(taskAddr.add(fieldPackagePtr));
                    if (!pkgPtr || pkgPtr < 0x10000) continue;
                    const convBase = ptr(pkgPtr).add(fieldConvString);
                    const convInfo = readStdString(convBase);
                    results.push({
                        task_addr: taskAddr.toString(),
                        pkg_ptr: '0x'+pkgPtr.toString(16),
                        conv_string: convInfo,
                        string_obj_addr: convBase.toString()
                    });
                }
            } catch(e){}
        }
        return results;
    },

    patchConvIdHeap: function(charPtrHex, newStr){
        const p = ptr(charPtrHex);
        try {
            const arr = new Uint8Array(newStr.length + 1);
            for (let i = 0; i < newStr.length; i++) arr[i] = newStr.charCodeAt(i);
            arr[newStr.length] = 0;
            p.writeByteArray(arr.buffer);
            // 读回验证（size 字节，不用 CString）
            const verifyArr = new Uint8Array(p.readByteArray(newStr.length));
            let verify = '';
            for (let i = 0; i < verifyArr.length; i++){
                const b = verifyArr[i];
                verify += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
            }
            return {ok: true, verify: verify};
        } catch(e){
            return {ok: false, err: e.message};
        }
    }
};
send({t:'ready'});
"""


def _build_frida_js(module_name: str = DEFAULT_MODULE_NAME) -> str:
    return _FRIDA_JS_TEMPLATE.replace("{MODULE_NAME}", module_name.lower())


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StdStringSnapshot:
    """扫堆时读到的 std::string 元信息 + 明文。"""

    size: int
    cap: int
    string_obj_addr: str
    heap_ptr: Optional[str]  # SSO 模式为 None
    sso: bool
    text: str

    @classmethod
    def from_js_dict(cls, d: dict[str, Any], string_obj_addr: str) -> "StdStringSnapshot":
        return cls(
            size=int(d.get("size", 0)),
            cap=int(d.get("cap", 0)),
            string_obj_addr=string_obj_addr,
            heap_ptr=d.get("ptr"),
            sso=bool(d.get("sso", False)),
            text=str(d.get("str", "")),
        )


@dataclass(frozen=True)
class TaskSnapshot:
    """扫到的一个活着的 PostSendMessageTask2 对象。"""

    task_addr: str
    package_ptr: str
    conv_string: StdStringSnapshot

    @classmethod
    def from_js_dict(cls, d: dict[str, Any]) -> "TaskSnapshot":
        conv_dict = d.get("conv_string") or {}
        string_obj_addr = d.get("string_obj_addr", "")
        return cls(
            task_addr=str(d.get("task_addr", "")),
            package_ptr=str(d.get("pkg_ptr", "")),
            conv_string=StdStringSnapshot.from_js_dict(conv_dict, string_obj_addr),
        )


@dataclass(frozen=True)
class PatchResult:
    ok: bool
    heap_ptr: str
    verify_read: Optional[str] = None
    error: Optional[str] = None


@dataclass
class HijackReport:
    """一次 hijack 会话的汇总。"""

    from_conv_id: str
    to_conv_id: str
    scans_done: int = 0
    tasks_seen_unique: int = 0
    tasks_matched: int = 0
    tasks_patched: int = 0
    duration_sec: float = 0.0
    timed_out: bool = False
    stopped: bool = False
    error: Optional[str] = None
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_conv_id": self.from_conv_id,
            "to_conv_id": self.to_conv_id,
            "scans_done": self.scans_done,
            "tasks_seen_unique": self.tasks_seen_unique,
            "tasks_matched": self.tasks_matched,
            "tasks_patched": self.tasks_patched,
            "duration_sec": round(self.duration_sec, 3),
            "timed_out": self.timed_out,
            "stopped": self.stopped,
            "error": self.error,
            "events": list(self.events),
        }


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class NativeRouterError(Exception):
    """所有 NativeRouter 相关异常的基类。"""


class NotAttachedError(NativeRouterError):
    """未 attach 就调用需要 attach 的方法。"""


class FridaUnavailableError(NativeRouterError):
    """frida 模块不可用（未安装或注入的 fake 为 None）。"""


# ---------------------------------------------------------------------------
# HijackHandle —— 后台 hijack 会话的句柄
# ---------------------------------------------------------------------------


class HijackHandle:
    """后台 hijack 循环的控制句柄。

    Args:
        router: 关联的 NativeRouter (仅用于线程内部访问 script)
        report: 结果聚合器 (线程内部持续更新)
        thread: 后台 worker 线程
        done_event: 线程结束标志
        patched_event: 至少 patch 过一次的标志

    生命周期::

        handle = router.arm(from_conv_id, to_conv_id, timeout_sec=30)
        # ... 主线程做 UIA 转发 ...
        handle.wait_for_patch(timeout=15)   # 等到至少一次成功 patch
        report = handle.wait(timeout=None)  # 阻塞到线程结束（或调 stop）
    """

    def __init__(
        self,
        report: HijackReport,
        thread: threading.Thread,
        done_event: threading.Event,
        patched_event: threading.Event,
        stop_event: threading.Event,
    ) -> None:
        self._report = report
        self._thread = thread
        self._done_event = done_event
        self._patched_event = patched_event
        self._stop_event = stop_event

    @property
    def report(self) -> HijackReport:
        """当前累计的结果（线程仍在运行时也可读，只读快照）。"""
        return self._report

    def is_done(self) -> bool:
        return self._done_event.is_set()

    def wait_for_patch(self, timeout: Optional[float] = None) -> bool:
        """阻塞直到 hijack 命中至少一次成功 patch。返回是否命中。"""
        return self._patched_event.wait(timeout=timeout)

    def wait(self, timeout: Optional[float] = None) -> HijackReport:
        """阻塞到 hijack 循环结束（超时/被停止/异常）。"""
        self._thread.join(timeout=timeout)
        return self._report

    def stop(self, *, timeout: Optional[float] = 5.0) -> HijackReport:
        """请求 hijack 循环立即停止，返回最终 report。"""
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        return self._report


# ---------------------------------------------------------------------------
# NativeRouter
# ---------------------------------------------------------------------------


class NativeRouter:
    """通过 Frida 只读扫堆 + heap 数据覆写实现 conv_id 重定向。

    典型用法::

        router = NativeRouter(pid=22184)
        router.attach()
        try:
            handle = router.arm(
                from_conv_id="S:...ORIG_35...",
                to_conv_id="S:...DEST_35...",
                timeout_sec=30,
            )
            # 主线程做 UIA 转发（长按 + 点转发 + 随便选个人）
            do_ui_forward(...)
            handle.wait_for_patch(timeout=15)
            report = handle.wait(timeout=None)
        finally:
            router.detach()

    Args:
        pid: 目标 wxwork.exe 进程 ID
        vtable_offset: PostSendMessageTask2 vtable 相对模块基址偏移。
            企微 5.0.10.6015 = ``0xabbb210``。企微升级需重新逆向。
        field_package_ptr: task 对象里 package_ptr 字段偏移（默认 0x30）
        field_conv_string: package 对象里 std::string 字段偏移（默认 0x28）
        module_name: 主模块名（默认 wxwork.exe）
        scan_interval_ms: 扫描 loop 间隔
        frida_module: 依赖注入用的 Frida 模块（测试用）。默认导入 ``frida``。
        clock: 依赖注入用的时钟函数，返回单调秒（测试用）。默认 ``time.monotonic``。
        sleep: 依赖注入用的 sleep 函数，接受秒（测试用）。默认 ``time.sleep``。
    """

    def __init__(
        self,
        pid: int,
        *,
        vtable_offset: int = DEFAULT_VTABLE_OFFSET,
        field_package_ptr: int = DEFAULT_FIELD_PACKAGE_PTR,
        field_conv_string: int = DEFAULT_FIELD_CONV_STRING,
        module_name: str = DEFAULT_MODULE_NAME,
        scan_interval_ms: int = DEFAULT_SCAN_INTERVAL_MS,
        frida_module: Any = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        script_load_timeout_s: float = 3.0,
    ) -> None:
        self.pid = int(pid)
        self.vtable_offset = int(vtable_offset)
        self.field_package_ptr = int(field_package_ptr)
        self.field_conv_string = int(field_conv_string)
        self.module_name = module_name
        self.scan_interval_ms = int(scan_interval_ms)
        self._clock = clock
        self._sleep = sleep
        self._script_load_timeout_s = float(script_load_timeout_s)

        if frida_module is None:
            try:
                import frida  # type: ignore
                frida_module = frida
            except ImportError:
                frida_module = None
        self._frida = frida_module

        self._session: Any = None
        self._script: Any = None
        self._script_ready: bool = False
        self._agent_base: Optional[str] = None

    # ------------------------------------------------------------------
    # Attach / detach
    # ------------------------------------------------------------------

    def attach(self) -> None:
        """Attach 到目标进程并加载 Frida 只读 agent。"""
        if self._frida is None:
            raise FridaUnavailableError(
                "frida module not available; install `frida` or inject via frida_module"
            )
        if self._session is not None:
            logger.debug("NativeRouter already attached to pid=%d", self.pid)
            return

        device = self._frida.get_local_device()
        self._session = device.attach(self.pid)
        self._script = self._session.create_script(_build_frida_js(self.module_name))
        self._script_ready = False
        self._agent_base = None
        self._script.on("message", self._on_message)
        self._script.load()

        # 等 ready 消息
        deadline = self._clock() + self._script_load_timeout_s
        while self._clock() < deadline:
            if self._script_ready:
                return
            self._sleep(0.05)
        # ready 未到但脚本已 load —— 允许继续（真机 Frida 有时 send 消息稍晚）
        logger.warning("NativeRouter script ready signal not received within %.1fs; continuing",
                       self._script_load_timeout_s)

    def detach(self) -> None:
        """卸载 agent 并断开会话。可重复调用。"""
        try:
            if self._script is not None:
                try:
                    self._script.unload()
                except Exception:
                    logger.debug("script.unload() raised", exc_info=True)
            if self._session is not None:
                try:
                    self._session.detach()
                except Exception:
                    logger.debug("session.detach() raised", exc_info=True)
        finally:
            self._script = None
            self._session = None
            self._script_ready = False
            self._agent_base = None

    @property
    def is_attached(self) -> bool:
        return self._script is not None

    @property
    def agent_base(self) -> Optional[str]:
        """已 attach 时，agent 报告的 wxwork.exe 基址。"""
        return self._agent_base

    def _on_message(self, message: dict[str, Any], data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            t = payload.get("t")
            if t == "ready":
                self._script_ready = True
            elif t == "info":
                msg = payload.get("msg", "")
                if "base=" in msg:
                    self._agent_base = msg.split("base=")[-1].strip()
                logger.info("frida: %s", msg)
        elif message.get("type") == "error":
            logger.warning("frida error: %s", message.get("description"))

    # ------------------------------------------------------------------
    # 单次操作（同步 RPC）
    # ------------------------------------------------------------------

    def _require_script(self) -> Any:
        if self._script is None:
            raise NotAttachedError("NativeRouter is not attached; call .attach() first")
        return self._script

    def scan_tasks(self) -> list[TaskSnapshot]:
        """扫一次堆，返回所有活着的 PostSendMessageTask2 对象。"""
        script = self._require_script()
        raw = script.exports_sync.scan_tasks(
            self.vtable_offset, self.field_package_ptr, self.field_conv_string
        )
        return [TaskSnapshot.from_js_dict(item) for item in (raw or [])]

    def patch_conv_id(self, heap_ptr: str, new_conv_id: str) -> PatchResult:
        """覆写 heap 上的 conv_id 数据（长度需与原字符串相同）。"""
        script = self._require_script()
        res = script.exports_sync.patch_conv_id_heap(heap_ptr, new_conv_id) or {}
        return PatchResult(
            ok=bool(res.get("ok")),
            heap_ptr=heap_ptr,
            verify_read=res.get("verify"),
            error=res.get("err"),
        )

    # ------------------------------------------------------------------
    # 后台 hijack 循环
    # ------------------------------------------------------------------

    def arm(
        self,
        from_conv_id: str,
        to_conv_id: str,
        *,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        max_patches: Optional[int] = None,
    ) -> HijackHandle:
        """启动后台扫描 + hijack 循环，返回句柄。

        Args:
            from_conv_id: 需要被替换的原 conv_id（严格匹配）
            to_conv_id: hijack 后的目标 conv_id（长度必须与 from 相同）
            timeout_sec: 后台循环最长运行时间（秒）
            max_patches: 命中 N 次成功 patch 后自动停止。None = 一直到 timeout。

        Raises:
            ValueError: conv_id 长度不匹配
            NotAttachedError: 未 attach

        Note:
            返回的 :class:`HijackHandle` 在调用方 stop 或 timeout 前不会关闭。
            调用方在 UIA 转发结束后应 ``handle.wait_for_patch(...)`` 再 ``handle.stop()``。
        """
        if len(from_conv_id) != len(to_conv_id):
            raise ValueError(
                f"conv_id length mismatch: from={len(from_conv_id)} to={len(to_conv_id)}; "
                f"same-length overwrite required"
            )
        self._require_script()

        report = HijackReport(from_conv_id=from_conv_id, to_conv_id=to_conv_id)
        done_event = threading.Event()
        patched_event = threading.Event()
        stop_event = threading.Event()

        def _worker() -> None:
            t0 = self._clock()
            deadline = t0 + float(timeout_sec)
            seen_tasks: set[str] = set()
            patched_addrs: set[str] = set()
            interval = max(self.scan_interval_ms, 10) / 1000.0
            try:
                while True:
                    if stop_event.is_set():
                        report.stopped = True
                        break
                    now = self._clock()
                    if now >= deadline:
                        report.timed_out = True
                        break

                    report.scans_done += 1
                    try:
                        tasks = self.scan_tasks()
                    except Exception as e:  # noqa: BLE001
                        report.error = f"scan_tasks failed: {e}"
                        logger.exception("scan_tasks failed in hijack worker")
                        break

                    for t in tasks:
                        if t.task_addr in seen_tasks:
                            continue
                        seen_tasks.add(t.task_addr)
                        report.tasks_seen_unique += 1

                        conv_text = t.conv_string.text
                        event: dict[str, Any] = {
                            "phase": "seen",
                            "elapsed": round(self._clock() - t0, 3),
                            "task": t.task_addr,
                            "pkg": t.package_ptr,
                            "str": conv_text,
                            "size": t.conv_string.size,
                        }

                        if conv_text != from_conv_id:
                            report.events.append(event)
                            continue

                        report.tasks_matched += 1

                        heap_ptr = t.conv_string.heap_ptr
                        if not heap_ptr:
                            event["phase"] = "matched_no_heap_ptr"
                            event["error"] = "std::string in SSO mode (size<=15), cannot in-place patch"
                            report.events.append(event)
                            continue

                        try:
                            pres = self.patch_conv_id(heap_ptr, to_conv_id)
                        except Exception as e:  # noqa: BLE001
                            event["phase"] = "matched_patch_exception"
                            event["error"] = str(e)
                            report.events.append(event)
                            logger.exception("patch_conv_id raised in hijack worker")
                            continue

                        if not pres.ok:
                            event["phase"] = "matched_patch_failed"
                            event["error"] = pres.error
                            report.events.append(event)
                            continue

                        patched_addrs.add(t.task_addr)
                        report.tasks_patched += 1
                        event["phase"] = "patched"
                        event["heap_ptr"] = heap_ptr
                        event["verify"] = pres.verify_read
                        report.events.append(event)
                        patched_event.set()

                        if max_patches is not None and report.tasks_patched >= max_patches:
                            break

                    if max_patches is not None and report.tasks_patched >= max_patches:
                        break

                    self._sleep(interval)
            finally:
                report.duration_sec = self._clock() - t0
                done_event.set()

        thread = threading.Thread(
            target=_worker,
            name=f"NativeRouter-hijack-pid{self.pid}",
            daemon=True,
        )
        thread.start()
        return HijackHandle(
            report=report,
            thread=thread,
            done_event=done_event,
            patched_event=patched_event,
            stop_event=stop_event,
        )

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "NativeRouter":
        self.attach()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.detach()


__all__ = [
    "DEFAULT_VTABLE_OFFSET",
    "DEFAULT_FIELD_PACKAGE_PTR",
    "DEFAULT_FIELD_CONV_STRING",
    "DEFAULT_MODULE_NAME",
    "DEFAULT_SCAN_INTERVAL_MS",
    "DEFAULT_TIMEOUT_SEC",
    "FridaUnavailableError",
    "HijackHandle",
    "HijackReport",
    "NativeRouter",
    "NativeRouterError",
    "NotAttachedError",
    "PatchResult",
    "StdStringSnapshot",
    "TaskSnapshot",
]
