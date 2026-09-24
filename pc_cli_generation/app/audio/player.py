"""
音频播放 — 定向到 VB-CABLE 虚拟麦克风。

关键：使用 CABLE Input 作为输出设备，配合 Windows 默认输入设备设为 CABLE Output，
      这样企微(在模拟器里)"以为"在录电脑麦克风，其实录到的是我们播放的音频。

用法：
    player = CablePlayer()
    dur = player.play_blocking(Path("prepared.wav"))
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

import numpy as np
import sounddevice as sd
import soundfile as sf
from loguru import logger


CABLE_INPUT_KEYWORD = "CABLE Input"
CABLE_OUTPUT_KEYWORD = "CABLE Output"


class VbCableNotFound(RuntimeError):
    pass


class CablePlayer:
    """使用 sounddevice 播放到 CABLE Input"""

    def __init__(self, device_keyword: str = CABLE_INPUT_KEYWORD) -> None:
        self.device_keyword = device_keyword

    @cached_property
    def device_index(self) -> int:
        for i, d in enumerate(sd.query_devices()):
            if d["max_output_channels"] > 0 and self.device_keyword in d["name"]:
                logger.debug(f"输出设备: [{i}] {d['name']}")
                return i
        raise VbCableNotFound(
            f"未找到输出设备 '{self.device_keyword}'。请确认 VB-CABLE 已安装。"
        )

    def play_blocking(self, wav_path: Path) -> float:
        """
        阻塞播放整个 wav 到 CABLE Input。返回音频时长 (秒)。
        """
        data, sr = sf.read(str(wav_path), dtype="float32", always_2d=False)
        if data.ndim > 1:
            data = data.mean(axis=1)  # 立体声折成单声道
        duration = len(data) / sr
        logger.info(
            f"▶ 播放到 {self.device_keyword}: {wav_path.name}  "
            f"{duration:.2f}s @ {sr}Hz"
        )
        sd.play(data, samplerate=sr, device=self.device_index, blocking=True)
        return duration


def check_default_input_is_cable() -> tuple[bool, str]:
    """
    检查 Windows 默认输入设备是不是 CABLE Output。
    返回 (是否正确, 当前名字)
    """
    try:
        idx = sd.default.device[0]
        name = sd.query_devices(idx)["name"]
        return (CABLE_OUTPUT_KEYWORD in name, name)
    except Exception as e:
        return (False, f"(unknown: {e})")
