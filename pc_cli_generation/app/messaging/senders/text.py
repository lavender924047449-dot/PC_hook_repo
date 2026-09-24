"""
TextSender — 文本消息 (Stage 4.5.2).

契约:
    - 属于 DIRECT_SEND_TYPES: targets=[单个联系人], 调用方已 open_chat 完毕
    - 只负责: 切文字模式 → 输入 → 点发送 → 等 UI 稳定

依赖:
    ctx.nav  : WeComNavigator (含 enter_text_mode / type_text / tap_send_button)
    ctx.cfg  : AppConfig (读取 timing.after_send_wait_s)
"""

from __future__ import annotations

import time
from typing import ClassVar

from loguru import logger

from app.messaging.sender import SendContext
from app.messaging.types import Message, MessageType


class TextSender:
    supported_types: ClassVar[frozenset[MessageType]] = frozenset({MessageType.TEXT})

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        if message.type is not MessageType.TEXT:
            raise ValueError(
                f"TextSender 只接收 TEXT, 收到 {message.type.value}"
            )
        if len(targets) != 1:
            raise ValueError(
                f"TextSender 只发单个联系人, 收到 targets={targets}"
            )
        if not message.text:
            raise ValueError("TEXT 消息 text 为空")

        contact = targets[0]
        nav = ctx.nav
        if nav is None:
            raise RuntimeError("SendContext.nav 未设置")

        logger.info(f"[text] → {contact!r}   ({len(message.text)} chars)")

        # 1) 确保是文字输入模式 (幂等)
        nav.enter_text_mode()

        # 2) 输入文本
        nav.type_text(message.text)

        # 3) 点发送
        after_wait = 1.0
        if ctx.cfg is not None:
            try:
                after_wait = float(ctx.cfg.timing.after_send_wait_s)
            except Exception:
                pass
        nav.tap_send_button(wait_after_s=after_wait)

        # 稳定期
        time.sleep(0.3)
