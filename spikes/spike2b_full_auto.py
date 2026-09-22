"""
Spike 2b: 全自动闭环 — 按下按钮 → 播放音频 → 松开按钮 → 发出气泡语音

依赖：
  - uiautomator2, adbutils, sounddevice, soundfile, numpy
  - MuMu 已跑起来 + adb 端口 16384 可达
  - Windows 默认输入设备已切到 CABLE Output
  - MuMu 正处于"企微 → 聊天窗口 → 语音输入模式"界面

用法：
  python spike2b_full_auto.py                # 用 test.wav
  python spike2b_full_auto.py path/to.wav    # 指定 wav

时序：
  T=0     按下 (adb touch down)
  T+150ms 开始播放音频到 CABLE Input
  T+150+D+300ms 松开 (发送)  (D = 音频时长)
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import adbutils
import numpy as np
import sounddevice as sd
import soundfile as sf
import uiautomator2 as u2


# 参数
BUTTON_RESOURCE_ID = "com.tencent.wework:id/ijs"
BUTTON_TEXT_FALLBACK = "按住"                 # textContains fallback
PRE_ROLL_MS = 150                             # 按下→开始播放 的缓冲
POST_ROLL_MS = 300                            # 播放结束→松开 的缓冲
MUMU_PORT = 16384                             # Spike 2a 验证过


# ---------- 音频 ---------- #

def find_cable_input() -> int:
    for i, d in enumerate(sd.query_devices()):
        if d["max_output_channels"] > 0 and "CABLE Input" in d["name"]:
            return i
    raise RuntimeError("找不到 CABLE Input 输出设备")


def load_audio(path: Path) -> tuple[np.ndarray, int]:
    data, sr = sf.read(str(path), dtype="float32", always_2d=False)
    if data.ndim > 1:
        data = data.mean(axis=1)
    return data, sr


# ---------- 设备 ---------- #

def connect_device() -> tuple[adbutils.AdbDevice, u2.Device]:
    adb = adbutils.adb
    devs = adb.device_list()
    if not devs:
        r = adb.connect(f"127.0.0.1:{MUMU_PORT}", timeout=2.0)
        print(f"  adb connect: {r}")
        devs = adb.device_list()
    if not devs:
        raise RuntimeError("adb 连不上 MuMu")
    ad = devs[0]
    d = u2.connect(ad.serial)
    return ad, d


def locate_button(d: u2.Device) -> tuple[int, int]:
    """返回按钮中心坐标 (x, y)"""
    el = d(resourceId=BUTTON_RESOURCE_ID)
    if not el.exists:
        el = d(textContains=BUTTON_TEXT_FALLBACK)
    if not el.exists:
        raise RuntimeError(
            f"找不到按钮 (resourceId={BUTTON_RESOURCE_ID} 或 textContains={BUTTON_TEXT_FALLBACK})\n"
            f"请确认 MuMu 里企微已进入语音输入模式"
        )
    b = el.info["bounds"]
    cx = (b["left"] + b["right"]) // 2
    cy = (b["top"] + b["bottom"]) // 2
    return cx, cy


# ---------- 精确按住 ---------- #

def _run_audio_after_delay(delay_ms: int, audio: np.ndarray,
                           sr: int, device: int, done_evt: threading.Event) -> None:
    """独立线程：延迟 N 毫秒后播放音频，播完 set event"""
    time.sleep(delay_ms / 1000)
    t0 = time.perf_counter()
    sd.play(audio, samplerate=sr, device=device, blocking=True)
    t1 = time.perf_counter()
    print(f"    [audio] 实际播放耗时 {(t1 - t0) * 1000:.0f}ms")
    done_evt.set()


def press_hold_release(d: u2.Device, x: int, y: int,
                       audio: np.ndarray, sr: int, out_dev: int) -> None:
    """核心时序：按下 → 延迟播放 → 播完 → 松开"""
    duration_s = len(audio) / sr
    total_hold_ms = PRE_ROLL_MS + int(duration_s * 1000) + POST_ROLL_MS

    print(f"  时序: 按下 → +{PRE_ROLL_MS}ms 播放 ({duration_s:.2f}s) → "
          f"+{POST_ROLL_MS}ms 松开   总按住 {total_hold_ms}ms")

    done = threading.Event()
    audio_thr = threading.Thread(
        target=_run_audio_after_delay,
        args=(PRE_ROLL_MS, audio, sr, out_dev, done),
        daemon=True,
    )

    # ▼ 按下
    t_start = time.perf_counter()
    d.touch.down(x, y)
    print(f"  ▼ down @ ({x}, {y})   t=0.000s")

    # 启动音频播放线程 (它会 sleep 150ms 再放)
    audio_thr.start()

    # 等音频播放完成
    audio_thr.join(timeout=duration_s + 5.0)
    if not done.is_set():
        print("  ⚠ 音频线程超时，仍尝试松开")

    # 追加 POST_ROLL 尾巴
    time.sleep(POST_ROLL_MS / 1000)

    # ▲ 松开
    d.touch.up(x, y)
    elapsed = time.perf_counter() - t_start
    print(f"  ▲ up   @ ({x}, {y})   t={elapsed:.3f}s   (预期 {total_hold_ms / 1000:.3f}s)")


# ---------- 主流程 ---------- #

def main() -> int:
    print("=" * 60)
    print("  Spike 2b: 全自动闭环 (按住 + 播放 + 发送)")
    print("=" * 60)

    # 1) 音频
    wav_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("test.wav")
    if not wav_path.exists():
        print(f"✗ 找不到音频: {wav_path}")
        return 1
    audio, sr = load_audio(wav_path)
    print(f"  音频: {wav_path.name}  {len(audio) / sr:.2f}s  {sr}Hz")

    # 2) CABLE Input
    try:
        out_dev = find_cable_input()
        print(f"  输出设备: [{out_dev}] {sd.query_devices(out_dev)['name']}")
    except RuntimeError as e:
        print(f"✗ {e}")
        return 2

    # 3) 检查 Windows 默认输入
    try:
        default_in = sd.default.device[0]
        name = sd.query_devices(default_in)["name"]
        if "CABLE Output" in name:
            print(f"  默认麦克风: {name}  ✓")
        else:
            print(f"  ⚠ 默认麦克风: {name}  (建议切到 CABLE Output)")
    except Exception:
        pass

    # 4) 连接设备
    print("\n== 连接 MuMu ==")
    try:
        ad, d = connect_device()
        print(f"  ✓ 已连接: {ad.serial}")
    except Exception as e:
        print(f"✗ {e}")
        return 3

    # 5) 定位按钮
    print("\n== 定位按钮 ==")
    print("  提示：确保 MuMu 里企微处于语音输入模式 (能看到 [按住 说话])")
    input("  按回车确认已就绪 > ")
    try:
        x, y = locate_button(d)
        print(f"  ✓ 按钮中心: ({x}, {y})")
    except Exception as e:
        print(f"✗ {e}")
        return 4

    # 6) 开始
    print("\n== 3 秒后开始全自动发送... ==")
    for i in range(3, 0, -1):
        print(f"  {i} ...")
        time.sleep(1)

    try:
        press_hold_release(d, x, y, audio, sr, out_dev)
    except Exception as e:
        print(f"✗ 按住/发送过程出错: {e}")
        # 兜底：确保松开
        try:
            d.touch.up(x, y)
        except Exception:
            pass
        return 5

    print("\n" + "=" * 60)
    print("  🎉 全流程完成，请查看 MuMu 里企微是否发出气泡语音")
    print("  预期：约 {:.1f}s 的气泡，播放为 test.wav 内容 (440Hz)".format(
        len(audio) / sr))
    print("=" * 60)

    ok = input("\n气泡是否符合预期? [y/N] > ").strip().lower()
    if ok == "y":
        print("\n🟢 Spike 2b 通过！核心链路完全打通。")
        print("   下一步：进入 Stage 1 — 项目脚手架 + 联系人切换")
        return 0
    print("\n🟡 请描述现象 (气泡时长 / 内容 / 是否发送)，我们排查")
    return 6


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
