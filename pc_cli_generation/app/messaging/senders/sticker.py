"""
StickerSender (Stage 4.5.8) — 收藏表情.

契约:
    - 属于 DIRECT_SEND_TYPES: targets=[单个联系人], 调用方已 open_chat 完毕
    - 走 emoji 面板 → 收藏 tab, 不走 FTA 转发路径
    - Message 字段: tag → AssetLibrary → AssetEntry.fta_locator
      (虽字段名叫 fta_locator, 对 STICKER 是"表情面板内定位串", 见下方语法)

Sticker locator 语法 (存在 AssetEntry.fta_locator):
    "idx:N"    第 N 张收藏表情 (0 = 最新/最左上)
    纯数字 "N"  等价于 "idx:N"
    "desc:XXX" 通过 content-desc 子串匹配 (适合有 accessibility label 的表情)

依赖:
    ctx.nav            : WeComNavigator (含 4.5.8 send_sticker)
    ctx.asset_library  : AssetLibrary
    ctx.cfg            : AppConfig (可选)

设计说明
========
STICKER 在项目里是"双重归类":
  * types.py DIRECT_SEND_TYPES  — 执行路径: 逐人打开聊天单独发送
  * asset_library.py FORWARD_ONLY_TYPES — 注册路径: 无本地文件, 用
    register_forward + fta_locator 登记
所以 StickerSender 是 Direct sender, 但依赖 AssetLibrary 查表.
"""

from __future__ import annotations

import time
from typing import ClassVar

from loguru import logger

from app.messaging.sender import SendContext
from app.messaging.types import Message, MessageType


class StickerSender:
    supported_types: ClassVar[frozenset[MessageType]] = frozenset(
        {MessageType.STICKER}
    )

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        # ---- 基础校验 ---- #
        if message.type is not MessageType.STICKER:
            raise ValueError(
                f"StickerSender 只接收 STICKER, 收到 {message.type.value}"
            )
        if len(targets) != 1:
            raise ValueError(
                f"StickerSender 只发单个联系人, 收到 {targets}"
            )
        if not message.tag:
            raise ValueError(
                "STICKER 消息 tag 为空 (应引用 AssetLibrary 中的 tag)"
            )

        nav = ctx.nav
        if nav is None:
            raise RuntimeError("SendContext.nav 未设置")
        lib = ctx.asset_library
        if lib is None:
            raise RuntimeError(
                "SendContext.asset_library 未设置; "
                "StickerSender 需要 AssetLibrary 查表情面板 locator"
            )

        # ---- 查 tag → AssetEntry → fta_locator ---- #
        entry = lib.get(message.tag)
        if entry.semantic_type is not MessageType.STICKER:
            raise ValueError(
                f"tag={message.tag!r} 的 semantic_type="
                f"{entry.semantic_type.value}, 与 STICKER 不符"
            )
        locator = (entry.fta_locator or "").strip()
        if not locator:
            raise ValueError(
                f"AssetEntry(tag={entry.tag!r}) 缺少 fta_locator "
                f"(表情面板内定位串); 注册时需提供"
            )

        contact = targets[0]
        logger.info(
            f"[sticker] → {contact!r}  tag={message.tag!r} locator={locator!r}"
        )

        # 读取发送后等待时间
        after = 1.0
        if ctx.cfg is not None:
            try:
                after = float(ctx.cfg.timing.after_send_wait_s)
            except Exception:
                pass

        # 委托 Navigator 完成完整链路
        nav.send_sticker(locator, after_send_s=after)

        time.sleep(0.3)
