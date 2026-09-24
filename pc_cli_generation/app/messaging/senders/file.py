"""
FileSender (Stage 4.5.4) — 任意本地文件.

新流程 (跳过 adb push, 走「预先发到文件传输助手」思路):
    * 用户预先把素材手动发到文件传输助手, Android 端企微接收 → SAF「最近」可见
    * message.path 语义改为 **文件名关键字** (SAF 里 textContains 命中)
      例: "Pupuapp"  或  "Pupuapp.docx"  或  "合同v3"

    1. Navigator.open_plus_panel()
    2. Navigator.open_file_picker()         → 点「文件」, 等来源弹窗
    3. Navigator.choose_local_file_source() → 点「从本地文件选择」
    4. Navigator.pick_file_by_name(keyword) → SAF「最近」textContains 命中并点击
    5. Navigator.tap_media_send()           → 确认发送
"""

from __future__ import annotations

import time
from typing import ClassVar

from loguru import logger

from app.messaging.sender import SendContext
from app.messaging.types import Message, MessageType


class FileSender:
    supported_types: ClassVar[frozenset[MessageType]] = frozenset(
        {MessageType.FILE}
    )

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        if message.type is not MessageType.FILE:
            raise ValueError(
                f"FileSender 只接收 FILE, 收到 {message.type.value}"
            )
        if len(targets) != 1:
            raise ValueError(f"FileSender 只发单个联系人, 收到 {targets}")
        if not message.path:
            raise ValueError("FILE 消息 path 为空 (应填 SAF 里可命中的文件名关键字)")

        nav = ctx.nav
        if nav is None:
            raise RuntimeError("SendContext.nav 未设置")

        keyword = message.path.strip()
        contact = targets[0]
        logger.info(f"[file] → {contact!r}   keyword={keyword!r}")

        # 1) → + → 文件 → 从本地文件选择 → SAF「最近」按关键字命中
        nav.open_plus_panel()
        nav.open_file_picker()
        nav.choose_local_file_source()
        nav.pick_file_by_name(keyword)

        # 2) 发送
        after = 1.5
        if ctx.cfg is not None:
            try:
                after = float(ctx.cfg.timing.after_send_wait_s)
            except Exception:
                pass
        nav.tap_media_send(wait_after_s=after)
        time.sleep(0.3)
