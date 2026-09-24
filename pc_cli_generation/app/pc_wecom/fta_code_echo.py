"""编码回写器：捕捉素材后立刻回写编码，默认不挂 UIA、不模拟鼠标。

企微对「UI Automation 附着 + 模拟鼠标」会弹出远程操作警告。
PC 客户端也没有公开的 headless 发消息接口，因此默认策略是：

1. 捕捉到文件后立刻把编码写入系统剪贴板（毫秒级，无 UI 注入）；
2. 若当前前台窗口已经是企微（用户刚把素材发到 FTA，输入框通常仍有焦点），
   只发送 Ctrl+V / Enter，不抢焦点、不点击、不连接 UIA；
3. 若企微不在前台，则只保留剪贴板，由用户在 FTA 里粘贴发送。

`--echo-ui` 才会走旧的 pywinauto 路径，该路径几乎一定触发远程操作警告。

v2 (2026-09-10): 可选注入 WeComMemoryReader，在 on_material_captured 时
自动扫描进程内存，将 send_time_ms 写入 BubbleAnchorService，使气泡定位
从"时间戳估算"升级为"内存精确锚点"。
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Callable, Literal

from loguru import logger

from app.messaging.cache_scanner import MaterialCaptured
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.pc_navigator import PCWeComNavigator

if TYPE_CHECKING:  # pragma: no cover
    from app.pc_wecom.wecom_memory_reader import WeComMemoryReader

EchoMode = Literal["clipboard", "paste_if_focused", "ui"]

try:  # pragma: no cover - 环境相关
    import win32clipboard
    import win32con
    import win32gui
    import win32api
    _HAS_WIN32 = True
except Exception:  # pragma: no cover
    _HAS_WIN32 = False

_VK_CONTROL = 0x11
_VK_V = 0x56
_VK_RETURN = 0x0D
_KEYEVENTF_KEYUP = 0x0002
_WECOM_CLASS = "WeWorkWindow"


def copy_text_to_clipboard(text: str, retries: int = 5) -> bool:
    payload = (text or "").strip()
    if not payload:
        return False
    box: list[bool | None] = [None]

    def _run() -> None:
        box[0] = _copy_text_blocking(payload, retries)

    worker = threading.Thread(target=_run, daemon=True, name="clipboard-write")
    worker.start()
    worker.join(0.4)
    if worker.is_alive():
        logger.warning("写入剪贴板超时，跳过本次回写（监听继续）")
        return False
    return bool(box[0])


def _copy_text_blocking(payload: str, retries: int) -> bool:
    if _HAS_WIN32:
        last_err: Exception | None = None
        for _ in range(max(1, retries)):
            try:
                win32clipboard.OpenClipboard()
                try:
                    win32clipboard.EmptyClipboard()
                    win32clipboard.SetClipboardText(payload, win32con.CF_UNICODETEXT)
                finally:
                    win32clipboard.CloseClipboard()
                return True
            except Exception as e:
                last_err = e
                time.sleep(0.02)
        logger.debug(f"win32clipboard 写入失败: {last_err}")
    try:
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(payload)
        r.update()
        r.destroy()
        return True
    except Exception as e:
        logger.warning(f"写入剪贴板失败: {e}")
        return False


def wecom_is_foreground() -> bool:
    if not _HAS_WIN32:
        return False
    try:
        hwnd = win32gui.GetForegroundWindow()
        if not hwnd:
            return False
        return win32gui.GetClassName(hwnd) == _WECOM_CLASS
    except Exception:
        return False


def paste_and_enter() -> bool:
    """仅发送 Ctrl+V 和 Enter，不改变焦点、不移动鼠标、不附着 UIA。"""
    if not _HAS_WIN32:
        return False
    try:
        win32api.keybd_event(_VK_CONTROL, 0, 0, 0)
        win32api.keybd_event(_VK_V, 0, 0, 0)
        win32api.keybd_event(_VK_V, 0, _KEYEVENTF_KEYUP, 0)
        win32api.keybd_event(_VK_CONTROL, 0, _KEYEVENTF_KEYUP, 0)
        time.sleep(0.04)
        win32api.keybd_event(_VK_RETURN, 0, 0, 0)
        win32api.keybd_event(_VK_RETURN, 0, _KEYEVENTF_KEYUP, 0)
        return True
    except Exception as e:
        logger.debug(f"Ctrl+V/Enter 发送失败: {e}")
        return False


class FtaCodeEcho:
    def __init__(
        self,
        anchor_service: BubbleAnchorService,
        *,
        navigator: PCWeComNavigator | None = None,
        mode: EchoMode = "paste_if_focused",
        dedup_window_s: float = 2.0,
        copy_text: Callable[[str], bool] | None = None,
        is_wecom_foreground: Callable[[], bool] | None = None,
        paste: Callable[[], bool] | None = None,
        memory_reader: "WeComMemoryReader | None" = None,
    ) -> None:
        if mode == "ui" and navigator is None:
            raise ValueError("mode='ui' 需要传入 PCWeComNavigator")
        self._anchor = anchor_service
        self._navigator = navigator
        self._mode: EchoMode = mode
        self._dedup_window_s = float(dedup_window_s)
        self._last_echo_at: dict[str, float] = {}
        self._copy_text = copy_text or copy_text_to_clipboard
        self._is_wecom_foreground = is_wecom_foreground or wecom_is_foreground
        self._paste = paste or paste_and_enter
        self._memory_reader = memory_reader  # WeComMemoryReader | None

    def on_material_captured(self, evt: MaterialCaptured) -> None:
        """素材捕获回调（非阻塞）。

        流程：
          1. 立即回写编码（echo）
          2. 用 captured_at 做初步 bind（毫秒级，不等内存扫描）
          3. 若有 memory_reader，启动后台线程做精确内存三元组扫描并更新 anchor
             （约 17–23s，不阻塞主线程）
        """
        code = (evt.entry.material_code or "").strip()
        if not code:
            return
        now = time.time()
        last_ts = self._last_echo_at.get(code, 0.0)
        should_echo = (now - last_ts) > self._dedup_window_s
        if should_echo:
            self._echo(code)
            self._last_echo_at[code] = now

        # 从 captured_at 解析近似发送时间（精度 1s，够用于初步 bind 和 UI 匹配）
        now_ms = int(time.time() * 1000)
        approx_send_time_ms: int = now_ms
        if hasattr(evt, "captured_at") and evt.captured_at:
            try:
                from datetime import datetime as _dt
                approx_send_time_ms = int(
                    _dt.fromisoformat(str(evt.captured_at)).timestamp() * 1000
                )
            except Exception:
                approx_send_time_ms = now_ms

        fingerprint = evt.entry.fingerprint or evt.entry.sha1 or ""
        echo_mid = f"echo-{evt.captured_at}"

        # 立即做初步 bind（无精确三元组，send_time_ms 来自文件时间戳）
        self._anchor.bind(
            code,
            fingerprint,
            echo_message_id=echo_mid,
            send_time_ms=approx_send_time_ms,
            sequence=0,
            wecom_message_id=0,
        )

        # 若有内存读取器，后台线程做精确扫描（~17–23s），完成后覆盖 anchor
        if self._memory_reader is not None:
            worker = threading.Thread(
                target=self._async_update_triplet,
                args=(code, fingerprint, echo_mid, approx_send_time_ms),
                daemon=True,
                name=f"memscan-{code[:12]}",
            )
            worker.start()

    def _async_update_triplet(
        self,
        code: str,
        fingerprint: str,
        echo_message_id: str,
        approx_send_time_ms: int,
    ) -> None:
        """后台线程：精确扫描内存三元组，完成后更新 anchor（覆盖初步 bind）。"""
        try:
            triplet = self._memory_reader.find_by_send_time(  # type: ignore[union-attr]
                approx_send_time_ms,
                tolerance_ms=30_000,
            )
            if triplet is not None:
                self._anchor.bind(
                    code,
                    fingerprint,
                    echo_message_id=echo_message_id,
                    send_time_ms=triplet.send_time_ms,
                    sequence=triplet.sequence,
                    wecom_message_id=triplet.message_id,
                )
                logger.debug(
                    f"[异步内存锚点] code={code} "
                    f"seq={triplet.sequence} ts_ms={triplet.send_time_ms} "
                    f"mid={triplet.message_id}"
                )
            else:
                logger.debug(f"[异步内存锚点] 未找到三元组: code={code}")
        except Exception as e:
            logger.debug(f"[异步内存锚点] 扫描失败（不影响主流程）: {e}")

    def _echo(self, code: str) -> None:
        if self._mode == "ui":
            assert self._navigator is not None
            self._navigator.send_text_to_active_window(code)
            logger.info(f"已用 UI 自动化回写编码: {code}")
            return

        copied = self._copy_text(code)
        if not copied:
            logger.warning(f"编码未能写入剪贴板: {code}")
            return

        if self._mode == "clipboard":
            logger.info(f"编码已复制到剪贴板（请在 FTA 按 Ctrl+V 回车）: {code}")
            return

        if self._is_wecom_foreground() and self._paste():
            logger.info(f"编码已粘贴发送（未使用 UIA/鼠标）: {code}")
        else:
            logger.info(f"编码已复制到剪贴板（企微不在前台，请切回 FTA 后 Ctrl+V 回车）: {code}")
