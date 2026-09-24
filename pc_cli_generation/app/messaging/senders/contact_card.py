"""
ContactCardSender (Stage 4.5.6) — 个人名片消息.

契约:
    - 属于 DIRECT_SEND_TYPES: targets=[单个联系人], 调用方已 open_chat 完毕
    - Message 字段: friend_name = 要作为名片分享出去的好友名
    - 只负责: "+" 面板 → 个人名片 → 选人 → 确认发送

依赖:
    ctx.nav  : WeComNavigator (含 4.5.6 新增的 send_contact_card)
    ctx.cfg  : AppConfig (读取 timing.after_send_wait_s)

注意:
    - 与 "企业名片" 是不同入口, Navigator 里明确用 "个人名片" 文本匹配
    - 若目标 friend_name 不在最近联系人, 会自动走搜索路径
"""

from __future__ import annotations

import time
from typing import ClassVar

from loguru import logger

from app.messaging.sender import SendContext
from app.messaging.types import Message, MessageType


class ContactCardSender:
    supported_types: ClassVar[frozenset[MessageType]] = frozenset(
        {MessageType.CONTACT_CARD}
    )

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        if message.type is not MessageType.CONTACT_CARD:
            raise ValueError(
                f"ContactCardSender 只接收 CONTACT_CARD, "
                f"收到 {message.type.value}"
            )
        if len(targets) != 1:
            raise ValueError(
                f"ContactCardSender 只发单个联系人, 收到 {targets}"
            )
        if not message.friend_name:
            raise ValueError("CONTACT_CARD 消息 friend_name 为空")

        nav = ctx.nav
        if nav is None:
            raise RuntimeError("SendContext.nav 未设置")

        contact = targets[0]
        friend = message.friend_name.strip()
        logger.info(
            f"[contact_card] → {contact!r}   分享 {friend!r} 的名片"
        )

        # 读取发送后等待时间
        after = 1.0
        if ctx.cfg is not None:
            try:
                after = float(ctx.cfg.timing.after_send_wait_s)
            except Exception:
                pass

        # 委托 Navigator 完成完整链路
        nav.send_contact_card(friend, after_send_s=after)

        # 额外稳定期 (与其他 sender 一致)
        time.sleep(0.3)
