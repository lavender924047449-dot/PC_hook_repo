"""
VoiceSender (Stage 4.5.4) — 复用现有 CablePlayer / AudioPreprocessor / gesture.

契约:
    - 属于 DIRECT_SEND_TYPES: targets=[单联系人], 已 open_chat
    - preflight: 检查 CABLE Input/Output 路由 (只做一次)
    - 预处理: 用 AudioPreprocessor 转成标准 WAV (幂等, 已有缓存)
    - 切语音模式 → 按住按钮 + 播放 blocking → 松开
    - 等待发送完成
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import ClassVar

from loguru import logger

from app.audio.player import CablePlayer, check_default_input_is_cable
from app.audio.preprocessor import AudioPreprocessor
from app.device.gestures import press_hold_and_run
from app.messaging.sender import SendContext
from app.messaging.types import Message, MessageType


class VoiceSender:
    supported_types: ClassVar[frozenset[MessageType]] = frozenset(
        {MessageType.VOICE}
    )

    def __init__(self) -> None:
        # 延迟到首次 send 时初始化 (需要 cfg)
        self._pre: AudioPreprocessor | None = None
        self._player: CablePlayer | None = None
        self._preflight_done: bool = False

    def _ensure_ready(self, ctx: SendContext) -> None:
        if ctx.cfg is None:
            raise RuntimeError("SendContext.cfg 未设置, VoiceSender 需要配置")
        if self._pre is None:
            self._pre = AudioPreprocessor(ctx.cfg.audio, ctx.cfg.ffmpeg)
        if self._player is None:
            self._player = CablePlayer()

    def _preflight(self) -> None:
        if self._preflight_done:
            return
        ok, name = check_default_input_is_cable()
        if not ok:
            logger.warning(
                f"Windows 默认输入不是 CABLE Output (当前: {name})——"
                f"MuMu 录到的会是本机麦克风。请先切换。"
            )
        # 触发 device_index 计算, 验证 CABLE Input 存在
        assert self._player is not None
        _ = self._player.device_index
        self._preflight_done = True

    def send(
        self,
        ctx: SendContext,
        targets: list[str],
        message: Message,
    ) -> None:
        if message.type is not MessageType.VOICE:
            raise ValueError(
                f"VoiceSender 只接收 VOICE, 收到 {message.type.value}"
            )
        if len(targets) != 1:
            raise ValueError(
                f"VoiceSender 只发单个联系人, 收到 {targets}"
            )
        if not message.path:
            raise ValueError("VOICE 消息 path 为空")

        nav = ctx.nav
        if nav is None:
            raise RuntimeError("SendContext.nav 未设置")

        self._ensure_ready(ctx)
        self._preflight()
        assert self._pre is not None and self._player is not None

        contact = targets[0]
        src = Path(message.path)
        if not src.is_file():
            raise FileNotFoundError(f"音频文件不存在: {src}")

        logger.info(f"[voice] → {contact!r}   file={src.name}")

        # 1) 预处理 (幂等缓存)
        prepared = self._pre.prepare(src)

        # 2) 切语音模式
        nav.enter_voice_mode()

        # 3) 定位 [按住 说话] 中心
        x, y = nav.button_center()
        logger.debug(f"按住说话按钮: ({x}, {y})")

        # 4) 按下 + 播放 + 松开
        pre_ms = int(ctx.cfg.timing.pre_roll_ms)
        post_ms = int(ctx.cfg.timing.post_roll_ms)
        hold = press_hold_and_run(
            ctx.dev, x, y,
            action=lambda: self._player.play_blocking(prepared.dst),
            pre_roll_ms=pre_ms,
            post_roll_ms=post_ms,
        )

        # 5) 等企微把语音气泡出栏
        after = float(ctx.cfg.timing.after_send_wait_s)
        time.sleep(after)

        logger.info(
            f"  ✓ 语音发出: {prepared.duration_s:.2f}s / 按住 {hold:.2f}s"
        )
