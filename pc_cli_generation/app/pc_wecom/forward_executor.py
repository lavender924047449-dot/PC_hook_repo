"""转发执行器：按编码定位气泡并转发到目标对象。

两阶段 API（产品化 ④）
----------------------
``prepare(material_code)`` 做到「长按气泡 + 点转发菜单」为止；
``send_to_target(target, *, conv_id=None)`` 负责选人并发送。

当 ``conv_id`` 注入时走 native 路径：在 ``pick_forward_menu()`` 之后、
``search_and_pick_contact`` 之前调用 ``NativeRouter.arm(from=占位联系人,
to=真实 conv_id)``，UIA 只选占位联系人，heap 覆写把消息重定向到真实目标。

``forward()`` 仍是 ``prepare + send_to_target`` 的便捷封装，保留重试语义。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.pc_navigator import BubbleAnchor, PCWeComNavigator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ForwardResult:
    ok: bool
    material_code: str
    target: str
    reason: str = ""
    conv_id: str = ""
    via_native: bool = False


@dataclass(frozen=True)
class PreparedForward:
    """``prepare()`` 完成后的会话状态：转发菜单已打开，等待选人。"""

    material_code: str
    bubble: BubbleAnchor


class ForwardExecutor:
    def __init__(
        self,
        navigator: PCWeComNavigator,
        anchor_service: BubbleAnchorService,
        *,
        native_router: Any = None,
        conv_resolver: Any = None,
        decoy_target: str | None = None,
        decoy_conv_id: str | None = None,
        hijack_timeout_sec: float = 30.0,
        hijack_wait_sec: float = 15.0,
        hijack_max_patches: int = 1,
    ) -> None:
        self._nav = navigator
        self._anchor = anchor_service
        self._native_router = native_router
        self._resolver = conv_resolver
        self._decoy_target = (decoy_target or "").strip() or None
        self._decoy_conv_id = (decoy_conv_id or "").strip() or None
        self._hijack_timeout_sec = float(hijack_timeout_sec)
        self._hijack_wait_sec = float(hijack_wait_sec)
        self._hijack_max_patches = int(hijack_max_patches)
        self._prepared: PreparedForward | None = None

    def prepare(self, material_code: str) -> PreparedForward:
        """定位气泡、打开 FTA、长按、点开转发菜单。不选人。"""
        a = self._anchor.locate(material_code)
        self._nav.open_fta()
        bubble = BubbleAnchor(
            material_code=material_code,
            bubble_timestamp=a.get("bubble_timestamp"),
            echo_message_id=a.get("echo_message_id"),
            fingerprint_snippet=a.get("fingerprint_snippet"),
            send_time_ms=a.get("send_time_ms", 0),
            sequence=a.get("sequence", 0),
            wecom_message_id=a.get("wecom_message_id", 0),
        )
        self._nav.long_press_bubble(bubble)
        self._nav.pick_forward_menu()
        prepared = PreparedForward(material_code=material_code, bubble=bubble)
        self._prepared = prepared
        return prepared

    def send_to_target(self, target: str, *, conv_id: str | None = None) -> ForwardResult:
        """在 ``prepare()`` 之后选人并确认发送。

        Args:
            target: UIA 搜索关键字。native 路径且配置了 ``decoy_target`` 时，
                实际点选的是占位联系人，``target`` 仅用于结果记录。
            conv_id: 若提供，走 ``NativeRouter.arm`` 重定向；否则纯 UIA。
        """
        prepared = self._prepared
        if prepared is None:
            raise RuntimeError("send_to_target() 需要先调用 prepare()")
        self._prepared = None

        dest = (conv_id or "").strip() or None
        if dest:
            if self._native_router is None:
                logger.warning(
                    "conv_id=%s 已提供但未注入 NativeRouter，回退 UIA 选人: %s",
                    dest,
                    target,
                )
                return self._send_uia(prepared, target)
            return self._send_native(prepared, target, dest)
        return self._send_uia(prepared, target)

    def forward(
        self,
        material_code: str,
        target: str,
        *,
        conv_id: str | None = None,
        retries: int = 2,
    ) -> ForwardResult:
        last_err = ""
        for _ in range(max(1, retries + 1)):
            try:
                self.prepare(material_code)
                return self.send_to_target(target, conv_id=conv_id)
            except Exception as e:
                last_err = str(e)
                self._prepared = None
        return ForwardResult(
            ok=False,
            material_code=material_code,
            target=target,
            reason=last_err,
            conv_id=(conv_id or ""),
            via_native=bool(conv_id),
        )

    # ------------------------------------------------------------------
    # 内部：UIA / native 两条发送路径
    # ------------------------------------------------------------------

    def _send_uia(self, prepared: PreparedForward, target: str) -> ForwardResult:
        picked = self._nav.search_and_pick_contact(target)
        if not picked:
            raise RuntimeError(f"未找到联系人: {target}")
        self._nav.confirm_send()
        return ForwardResult(ok=True, material_code=prepared.material_code, target=target)

    def _send_native(
        self,
        prepared: PreparedForward,
        target: str,
        conv_id: str,
    ) -> ForwardResult:
        ui_target = self._decoy_target or target
        from_id = self._resolve_from_conv_id(ui_target)

        # 占位联系人就是真实目标：无需 hijack，退回 UIA 点选真实 target
        if from_id and from_id == conv_id:
            logger.info("from_conv_id == to_conv_id，跳过 hijack，走 UIA: %s", target)
            return self._send_uia(prepared, target)

        if not from_id:
            raise RuntimeError(
                f"无法解析 UI 占位联系人 conv_id（decoy={ui_target!r}）；"
                "请配置 decoy_conv_id 或注入 ContactConvResolver"
            )

        router = self._native_router
        if not getattr(router, "is_attached", False):
            router.attach()

        # ★ 注入点：pick_forward_menu 之后、search_and_pick_contact 之前
        handle = router.arm(
            from_id,
            conv_id,
            timeout_sec=self._hijack_timeout_sec,
            max_patches=self._hijack_max_patches,
        )
        try:
            picked = self._nav.search_and_pick_contact(ui_target)
            if not picked:
                raise RuntimeError(f"未找到联系人: {ui_target}")
            self._nav.confirm_send()
            if not handle.wait_for_patch(timeout=self._hijack_wait_sec):
                raise RuntimeError(
                    f"native hijack 未命中: from={from_id!r} to={conv_id!r}"
                )
        finally:
            stop = getattr(handle, "stop", None)
            if callable(stop):
                try:
                    stop(timeout=2.0)
                except Exception:
                    logger.debug("HijackHandle.stop() raised", exc_info=True)

        return ForwardResult(
            ok=True,
            material_code=prepared.material_code,
            target=target,
            conv_id=conv_id,
            via_native=True,
        )

    def _resolve_from_conv_id(self, ui_target: str) -> Optional[str]:
        if self._decoy_conv_id:
            return self._decoy_conv_id
        resolver = self._resolver
        if resolver is None:
            return None
        resolve = getattr(resolver, "resolve", None)
        if not callable(resolve):
            return None
        hit = resolve(ui_target)
        return str(hit).strip() if hit else None
