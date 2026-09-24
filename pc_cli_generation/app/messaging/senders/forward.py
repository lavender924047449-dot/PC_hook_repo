"""
ForwardSender — 转发类消息统一 Sender (Stage 4.5.5.3 起, 4.5.7 加多选).

支持 MessageType:
    MINIPROGRAM / CHANNEL_VIDEO / LOCATION  (即 FORWARD_TYPES)

发送模式 (mode):
    "auto"    — 默认. 单人走单选, 多人走多选; 多选未勾中的联系人回退单选
    "single"  — 4.5.5.3 老行为: 每个联系人独立走一次单选转发
    "multi"   — 4.5.7 优化: 一次多选群发; 未勾中的联系人抛异常 (不 fallback)

依赖:
    ctx.nav            : WeComNavigator (4.5.5.2 单选 + 4.5.7 多选方法)
    ctx.asset_library  : AssetLibrary
    ctx.cfg            : AppConfig (可选)
"""

from __future__ import annotations

import time
from typing import ClassVar, Literal

from loguru import logger

from app.messaging.sender import SendContext
from app.messaging.types import FORWARD_TYPES, Message, MessageType


ForwardMode = Literal["auto", "single", "multi"]


class ForwardSender:
    supported_types: ClassVar[frozenset[MessageType]] = FORWARD_TYPES

    #: 单选路径下, 每人转发完成后停顿 (让 UI 稳定 + 避风控)
    _AFTER_EACH_S: float = 0.5

    def __init__(self, mode: ForwardMode = "auto") -> None:
        if mode not in ("auto", "single", "multi"):
            raise ValueError(f"未知 mode={mode!r}")
        self.mode: ForwardMode = mode

    # ---------------- Entry ---------------- #

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        # ---- 基础校验 ---- #
        if message.type not in FORWARD_TYPES:
            raise ValueError(
                f"ForwardSender 只接收 {sorted(t.value for t in FORWARD_TYPES)}, "
                f"收到 {message.type.value}"
            )
        if not message.tag:
            raise ValueError(
                f"{message.type.value} 消息 tag 为空 "
                f"(应引用 AssetLibrary 中的 tag)"
            )
        if not targets:
            raise ValueError("ForwardSender: targets 不能为空")

        nav = ctx.nav
        if nav is None:
            raise RuntimeError("SendContext.nav 未设置")
        lib = ctx.asset_library
        if lib is None:
            raise RuntimeError(
                "SendContext.asset_library 未设置; "
                "ForwardSender 需要 AssetLibrary 查 fta_locator"
            )

        # ---- 查 tag → AssetEntry → fta_locator ---- #
        entry = lib.get(message.tag)
        if entry.semantic_type is not message.type:
            raise ValueError(
                f"tag={message.tag!r} 的 semantic_type={entry.semantic_type.value}, "
                f"与消息 type={message.type.value} 不符"
            )
        fta_locator = (entry.fta_locator or "").strip()
        if not fta_locator:
            raise ValueError(
                f"AssetEntry(tag={entry.tag!r}) 缺少 fta_locator; "
                f"转发类素材必须在注册时提供 fta_locator"
            )

        # ---- 选择执行路径 ---- #
        use_multi = self._should_use_multi(len(targets))
        logger.info(
            f"[forward:{message.type.value}] tag={message.tag!r} "
            f"locator={fta_locator!r} → {len(targets)} 人  "
            f"[mode={self.mode}, path={'multi' if use_multi else 'single'}]"
        )

        # 打开 FTA (无论走哪条路径, 都需要在 FTA)
        nav.open_fta()

        if use_multi:
            self._send_multi(nav, fta_locator, list(targets))
        else:
            self._send_single_loop(nav, fta_locator, list(targets))

    # ---------------- 路径判定 ---------------- #

    def _should_use_multi(self, n_targets: int) -> bool:
        if n_targets <= 1:
            return False   # 单人不走多选
        if self.mode == "single":
            return False
        # "auto" 或 "multi" 且 n>=2
        return True

    # ---------------- 多选路径 ---------------- #

    def _send_multi(
        self,
        nav,
        fta_locator: str,
        targets: list[str],
    ) -> None:
        """
        走一次多选群发. 未勾中的联系人:
          - mode="multi" (strict): 汇总抛异常
          - mode="auto": 回退到单选循环
        """
        missed = nav.forward_bubble_multi(fta_locator, targets)
        if not missed:
            logger.info(f"[forward] 多选成功, 全部 {len(targets)} 人已发送")
            return

        if self.mode == "multi":
            raise RuntimeError(
                f"ForwardSender(mode=multi) 未勾中: "
                f"{len(missed)}/{len(targets)} 人: {missed}"
            )

        # mode="auto": 回退单选处理 missed
        logger.warning(
            f"[forward] 多选路径未勾中 {len(missed)} 人, 回退单选: {missed}"
        )
        try:
            nav.open_fta()
        except Exception as e:
            raise RuntimeError(
                f"多选后回退到单选前 open_fta 失败: {e}"
            ) from e
        self._send_single_loop(nav, fta_locator, missed)

    # ---------------- 单选路径 (4.5.5.3 老行为) ---------------- #

    def _send_single_loop(
        self,
        nav,
        fta_locator: str,
        targets: list[str],
    ) -> None:
        errors: list[tuple[str, Exception]] = []
        for i, contact in enumerate(targets):
            logger.debug(
                f"[forward-single] {i + 1}/{len(targets)} → {contact!r}"
            )
            try:
                nav.forward_bubble_to(fta_locator, contact)
            except Exception as e:
                logger.error(
                    f"[forward-single] 转发失败 {contact!r}: {e}"
                )
                errors.append((contact, e))
                try:
                    nav.open_fta()
                except Exception as e2:
                    logger.error(
                        f"[forward-single] 恢复回 FTA 失败: {e2}"
                    )
                    raise
                continue

            # 下一轮前回到 FTA (最后一轮不需要)
            if i < len(targets) - 1:
                time.sleep(self._AFTER_EACH_S)
                nav.open_fta()

        if errors:
            failed = ", ".join(c for c, _ in errors)
            raise RuntimeError(
                f"ForwardSender 部分失败: {len(errors)}/{len(targets)} "
                f"人未成功: {failed}"
            )
