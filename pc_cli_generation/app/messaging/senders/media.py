"""
ImageSender / VideoSender — 图片、视频 (Stage 4.5.3).

流程 (与 TextSender 一样, 假定 open_chat 已完成):
    1. AndroidFileStore.ensure(local_path) → adb push + MediaScanner
    2. Navigator.open_plus_panel()
    3. Navigator.open_gallery()
    4. Navigator.pick_latest_in_gallery(prefer_name_substring=...)
    5. Navigator.tap_media_send()

共享一个 MediaSender 基类, IMAGE / VIDEO 只是 supported_types 不同.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import ClassVar

from loguru import logger

from app.messaging.sender import SendContext
from app.messaging.types import Message, MessageType


class MediaSender:
    """图片/视频公共实现. 子类通过 supported_types 声明自己发哪个."""

    supported_types: ClassVar[frozenset[MessageType]]

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        if message.type not in self.supported_types:
            raise ValueError(
                f"{type(self).__name__} 不接收 {message.type.value}"
            )
        if len(targets) != 1:
            raise ValueError(
                f"{type(self).__name__} 只发单个联系人, 收到 {targets}"
            )
        if not message.path:
            raise ValueError(f"{message.type.value} 消息 path 为空")

        nav = ctx.nav
        # Stage 4.5.5.4: file_store 字段与 asset_library 分离; 兼容旧代码若还挂在 asset_library
        store = ctx.file_store or ctx.asset_library
        if nav is None:
            raise RuntimeError("SendContext.nav 未设置")
        if store is None:
            raise RuntimeError(
                "SendContext.file_store 未设置 (需要 AndroidFileStore)"
            )

        local = Path(message.path)
        if not local.is_file():
            raise FileNotFoundError(f"本地媒体文件不存在: {local}")

        contact = targets[0]
        logger.info(
            f"[{message.type.value}] → {contact!r}   file={local.name}"
        )

        # 1) push 到设备 (幂等)
        remote = store.ensure(local)
        # 从 remote 路径末段拿"文件名子串"用于相册二次匹配
        name_hint = Path(remote).name

        # 2) 打开附件面板 → 相册
        nav.open_plus_panel()
        nav.open_gallery()

        # 3) 挑中最新一张 (优先按文件名匹配, 兜底左上角)
        nav.pick_latest_in_gallery(prefer_name_substring=name_hint)

        # 4) 点右下"发送(N)"
        after = 1.5
        if ctx.cfg is not None:
            try:
                after = float(ctx.cfg.timing.after_send_wait_s)
            except Exception:
                pass
        nav.tap_media_send(wait_after_s=after)

        time.sleep(0.3)


class ImageSender(MediaSender):
    supported_types: ClassVar[frozenset[MessageType]] = frozenset(
        {MessageType.IMAGE}
    )


class VideoSender(MediaSender):
    supported_types: ClassVar[frozenset[MessageType]] = frozenset(
        {MessageType.VIDEO}
    )
