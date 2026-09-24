"""
VoiceSender — 顶层编排：预处理 → 导航 → 按住+播放+松开 → 完成。

DEPRECATED: Android 链路已由 PC 企微 FTA 主链路取代，仅保留兼容。

用法：
    from app.config import get_config
    from app.device.adb import AdbSession
    from app.automation.sender import VoiceSender

    with AdbSession() as sess:
        sender = VoiceSender.from_config(sess.dev, get_config())
        sender.send("测试语音群", Path("hello.wav"))
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

import uiautomator2 as u2
from loguru import logger

from app.audio.player import CablePlayer, check_default_input_is_cable
from app.audio.preprocessor import AudioPreprocessor, PreparedAudio
from app.automation.navigator import WeComNavigator
from app.config import AppConfig
from app.device.gestures import press_hold_and_run


@dataclass(slots=True)
class SendResult:
    contact: str
    src: Path
    prepared: PreparedAudio
    duration_s: float
    hold_actual_s: float


class VoiceSender:
    """一键发送一条语音气泡。"""

    def __init__(
        self,
        dev: u2.Device,
        cfg: AppConfig,
        preprocessor: AudioPreprocessor,
        player: CablePlayer,
        navigator: WeComNavigator,
    ) -> None:
        self.dev = dev
        self.cfg = cfg
        self.pre = preprocessor
        self.player = player
        self.nav = navigator

    @classmethod
    def from_config(cls, dev: u2.Device, cfg: AppConfig) -> "VoiceSender":
        return cls(
            dev=dev,
            cfg=cfg,
            preprocessor=AudioPreprocessor(cfg.audio, cfg.ffmpeg),
            player=CablePlayer(),
            navigator=WeComNavigator(dev, cfg.locators),
        )

    # ---------------- 前置检查 ---------------- #
    def preflight(self) -> None:
        ok, name = check_default_input_is_cable()
        if not ok:
            logger.warning(
                f"Windows 默认输入不是 CABLE Output（当前: {name}）——"
                f"MuMu 录到的会是本机麦克风。请先切换。"
            )
        # 触发一次 device_index 计算，验证 CABLE Input 存在
        _ = self.player.device_index

    # ---------------- 单条发送 ---------------- #
    def send(self, contact: str, audio_src: Path | str) -> SendResult:
        audio_src = Path(audio_src)
        logger.info(f"── send: {contact!r} ← {audio_src.name} ──")

        # 1) 前置检查
        self.preflight()

        # 2) 预处理音频
        prepared = self.pre.prepare(audio_src)

        # 3) 导航到聊天 → 语音输入模式
        self.nav.goto_home()
        self.nav.open_chat(contact)
        self.nav.enter_voice_mode()

        # 4) 定位按钮
        x, y = self.nav.button_center()
        logger.info(f"按钮中心: ({x}, {y})")

        # 5) 精确按下 + 播放 + 松开
        hold = press_hold_and_run(
            self.dev, x, y,
            action=lambda: self.player.play_blocking(prepared.dst),
            pre_roll_ms=self.cfg.timing.pre_roll_ms,
            post_roll_ms=self.cfg.timing.post_roll_ms,
        )

        # 6) 等企微完成发送
        time.sleep(self.cfg.timing.after_send_wait_s)
        logger.info(
            f"✓ 已发送 {contact!r}  "
            f"音频 {prepared.duration_s:.2f}s / 按住 {hold:.2f}s"
        )

        return SendResult(
            contact=contact,
            src=audio_src,
            prepared=prepared,
            duration_s=prepared.duration_s,
            hold_actual_s=hold,
        )
