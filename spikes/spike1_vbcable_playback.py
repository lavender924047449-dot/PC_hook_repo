"""
Spike 1: VB-CABLE 音频通路验证 (独立验证脚本，非项目正式代码)

目标：
  证明 Python 能把音频精准送到 VB-CABLE 虚拟麦克风，供企业微信录制。

验证链路：
  test.wav (或程序生成的测试音)
      ↓ sounddevice
  CABLE Input (虚拟扬声器)
      ↓ VB-CABLE 内部环回
  CABLE Output (虚拟麦克风) ← Windows 默认输入设备
      ↓
  企业微信 "按住说话" → 录到并发送

用法：
  python spike1_vbcable_playback.py               # 使用生成的 3 秒测试音
  python spike1_vbcable_playback.py path/to.wav   # 使用指定 wav 文件

操作步骤：
  1. 先在 Windows 声音设置中把默认输入设备改为 "CABLE Output"
     (或本脚本可选自动切换，Spike 1 阶段先手动切以便观察)
  2. 打开企业微信，找一个"文件传输助手"或私聊窗口
  3. 按脚本提示，长按"按住说话"，等待脚本播放完成再松开
  4. 检查企微收到的语音是否清晰、时长匹配
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import sounddevice as sd
import soundfile as sf


# ------------------------- 工具 ------------------------- #

def find_cable_input() -> int:
    """返回 CABLE Input 的输出设备索引"""
    for i, d in enumerate(sd.query_devices()):
        if d["max_output_channels"] > 0 and "CABLE Input" in d["name"]:
            return i
    raise RuntimeError("未找到 'CABLE Input' 输出设备，请确认 VB-CABLE 已安装。")


def find_cable_output() -> int | None:
    """返回 CABLE Output 的输入设备索引 (仅用于打印提示)"""
    for i, d in enumerate(sd.query_devices()):
        if d["max_input_channels"] > 0 and "CABLE Output" in d["name"]:
            return i
    return None


def gen_test_tone(seconds: float = 3.0, sr: int = 48000) -> np.ndarray:
    """
    生成一段 3 秒的"1-2-3-2-1"音阶提示音 (mono, float32)。
    便于人耳判断是否被完整录制、有无截断。
    """
    freqs = [523, 659, 784, 659, 523]  # C5 E5 G5 E5 C5
    seg = seconds / len(freqs)
    t_seg = np.linspace(0, seg, int(sr * seg), endpoint=False, dtype=np.float32)
    envelope = np.hanning(len(t_seg)).astype(np.float32)  # 消除爆音
    audio = np.concatenate(
        [np.sin(2 * np.pi * f * t_seg) * envelope * 0.6 for f in freqs]
    )
    # 前后各加 100ms 静音，模拟真实使用中"按下→播放"的缓冲
    pad = np.zeros(int(sr * 0.1), dtype=np.float32)
    return np.concatenate([pad, audio, pad])


def load_wav(path: Path) -> tuple[np.ndarray, int]:
    """读取 WAV 并返回 (samples, sample_rate)，自动转 float32 mono"""
    data, sr = sf.read(str(path), dtype="float32", always_2d=False)
    if data.ndim > 1:
        data = data.mean(axis=1)  # 立体声转单声道
    return data, sr


# ------------------------- 主流程 ------------------------- #

def main() -> int:
    print("=" * 60)
    print("  Spike 1: VB-CABLE 音频通路验证")
    print("=" * 60)

    # 1) 定位 VB-CABLE 设备
    try:
        out_idx = find_cable_input()
    except RuntimeError as e:
        print(f"✗ {e}")
        return 1

    in_idx = find_cable_output()
    print(f"✓ 输出目标: [{out_idx}] {sd.query_devices(out_idx)['name']}")
    if in_idx is not None:
        print(f"✓ 对应虚拟麦克风: [{in_idx}] {sd.query_devices(in_idx)['name']}")

    # 2) 准备音频
    if len(sys.argv) > 1:
        wav_path = Path(sys.argv[1])
        if not wav_path.exists():
            print(f"✗ 找不到文件: {wav_path}")
            return 1
        audio, sr = load_wav(wav_path)
        print(f"✓ 读取音频: {wav_path.name}  "
              f"{len(audio) / sr:.2f}s  {sr}Hz")
    else:
        sr = 48000
        audio = gen_test_tone(seconds=3.0, sr=sr)
        print(f"✓ 生成测试音: 3.0s 音阶 (C-E-G-E-C) @ {sr}Hz")

    duration = len(audio) / sr

    # 3) 提示当前默认输入设备
    try:
        default_in_idx = sd.default.device[0]
        default_in_name = sd.query_devices(default_in_idx)["name"]
        print(f"\n当前系统默认麦克风: {default_in_name}")
        if "CABLE Output" not in default_in_name:
            print("  ⚠ 不是 CABLE Output。企业微信可能仍在录本机麦克风。")
            print("  → 请到 Windows [声音设置 → 输入] 手动切换到 'CABLE Output'")
            print("    (未来正式版会用 pycaw 自动切换)")
        else:
            print("  ✓ 已指向 VB-CABLE，可以直接被企微录到")
    except Exception as e:
        print(f"  (未能读取默认输入设备: {e})")

    # 4) 交互 (倒计时模式)
    print("\n--- 请打开 MuMu → 企微 → 聊天窗口 → 点 🎙️ 切到语音输入 ---")
    print(f"\n准备播放 {duration:.2f} 秒音频到 CABLE Input")
    print("操作流程：")
    print("  1) 按回车启动 5 秒倒计时")
    print("  2) 立即切到 MuMu，按住 [按住说话] 按钮不放")
    print("  3) 等待倒计时结束 → 自动播放")
    print(f"  4) 播放持续 {duration:.2f}s + 松手缓冲 → 松开按钮")
    input("\n[回车键] 启动倒计时 > ")

    countdown = 5
    for i in range(countdown, 0, -1):
        print(f"  {i} ...  (快切到 MuMu 按住按钮)")
        time.sleep(1)

    # 5) 播放
    print(f"▶ 开始播放... (预计 {duration:.2f}s，请保持按住按钮)")
    t0 = time.perf_counter()
    sd.play(audio, samplerate=sr, device=out_idx, blocking=True)
    t1 = time.perf_counter()
    print(f"⏹ 播放结束，实际耗时 {t1 - t0:.3f}s")
    print("\n请等待 ~200ms 后再松开企微按钮，然后检查语音气泡：")
    print("  1) 时长是否接近 {:.1f}s".format(duration))
    print("  2) 是否听到完整的 C-E-G-E-C 音阶 (或你的 wav 内容)")
    print("  3) 开头/结尾有无被截掉")

    # 6) 结果确认
    print("\n" + "-" * 60)
    ok = input("发送后，气泡语音是否符合预期? [y/N] > ").strip().lower()
    if ok == "y":
        print("\n✔ Spike 1 通过！VB-CABLE 音频通路可用。")
        print("  下一步可进入 Spike 2: pywinauto 定位企微窗口。")
        return 0
    else:
        print("\n✗ Spike 1 未通过，可能原因：")
        print("  - 默认麦克风未切到 CABLE Output")
        print("  - 企微在麦克风选择里指定了其他设备 (企微设置→通用→音视频)")
        print("  - CABLE Input 播放音量为 0 (Windows 音量合成器)")
        print("  - 按住时长 < 音频时长")
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
