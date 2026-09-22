"""
Spike 3: 联系人/群搜索 + 打开聊天 + 切到语音输入模式 + 全自动发送

流程：
  企微 (任意界面)
    → 回到消息首页
    → 点顶部搜索 🔍
    → 输入群名/联系人名
    → 点击首个结果
    → 进入聊天窗口
    → 点 🎙️ 切语音输入
    → [Spike 2b 逻辑] 按下 + 播放 + 松开 → 发送气泡

用法：
  python spike3_contact_switch.py "群或联系人名"
  python spike3_contact_switch.py "群或联系人名" test.wav
  python spike3_contact_switch.py "群或联系人名" test.wav --dry-run   # 只导航不发送

失败时会 dump 当前 UI 到 dump_step<N>.xml，方便分析选择器。
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


# ---------- 参数 ---------- #
MUMU_PORT = 16384
BUTTON_RESOURCE_ID = "com.tencent.wework:id/ijs"    # 按住说话 (Spike 2a 拿到)
PRE_ROLL_MS = 150
POST_ROLL_MS = 300


# 各步骤可能的选择器 (多组 fallback)
SEARCH_ICON_CANDIDATES = [
    dict(description="搜索"),
    dict(descriptionContains="搜索"),
    dict(text="搜索"),
    # 常见 resourceId 猜测
    dict(resourceIdMatches=r".*(search|Search).*"),
]

SEARCH_INPUT_CANDIDATES = [
    dict(className="android.widget.EditText"),
    dict(descriptionContains="搜索"),
    dict(text="搜索"),
]

MIC_ICON_CANDIDATES = [
    # 已通过 dump 分析确认: 输入区左侧的语音/键盘切换图标
    dict(resourceId="com.tencent.wework:id/gif"),
    # 兜底
    dict(description="切换到语音输入"),
    dict(descriptionContains="语音"),
]

HOME_TAB_CANDIDATES = [
    dict(text="消息"),
    dict(description="消息"),
]


# ---------- 通用工具 ---------- #

def try_locate(d: u2.Device, candidates: list[dict], step_name: str,
               dump_dir: Path) -> u2.UiObject | None:
    """按顺序尝试多组选择器，命中即返回"""
    for i, sel in enumerate(candidates):
        try:
            el = d(**sel)
            if el.exists:
                print(f"    ✓ 命中 [{i}] {sel}")
                return el
        except Exception as e:
            print(f"    ✗ [{i}] {sel}  ({e})")
    # 失败 → dump
    xml = d.dump_hierarchy()
    dump_path = dump_dir / f"dump_{step_name}.xml"
    dump_path.write_text(xml, encoding="utf-8")
    print(f"    ✗ 未命中，UI 树已保存: {dump_path.name}")
    return None


def take_screenshot(d: u2.Device, path: Path) -> None:
    try:
        d.screenshot(str(path))
        print(f"    📸 截图: {path.name}")
    except Exception:
        pass


def go_home(d: u2.Device) -> None:
    """尽力回到企微消息列表"""
    print("\n[Step A] 回到消息首页")
    # 连续 back 几次，直到看到消息 tab
    for i in range(5):
        home = d(**HOME_TAB_CANDIDATES[0])
        if home.exists and home.info.get("selected", False):
            print("    ✓ 已在消息列表")
            return
        if home.exists:
            home.click()
            time.sleep(0.5)
            print("    ✓ 点击 '消息' tab")
            return
        d.press("back")
        time.sleep(0.3)
    print("    ⚠ 可能不在消息列表，继续尝试后续步骤")


# ---------- 步骤实现 ---------- #

def click_from_list_directly(d: u2.Device, name: str) -> bool:
    """路径 A: 若名字已在消息列表中可见，直接点击"""
    print(f"\n[Step B-A] 尝试直接从消息列表点击 '{name}'")
    el = d(text=name)
    if el.exists:
        info = el.info
        b = info.get("bounds", {})
        print(f"    ✓ 已找到 text='{name}'  bounds={b}")
        el.click()
        time.sleep(1.5)
        return True
    el = d(textContains=name)
    if el.exists:
        print(f"    ✓ 已找到 textContains='{name}'")
        el.click()
        time.sleep(1.5)
        return True
    print(f"    · 列表中未见 '{name}'，尝试下拉搜索")
    return False


def swipe_down_to_reveal_search(d: u2.Device, dump_dir: Path) -> bool:
    """路径 B: 下拉消息列表调出搜索栏"""
    print("\n[Step B-B] 下拉列表调出搜索栏")
    w = d.info["displayWidth"]
    h = d.info["displayHeight"]
    # 从列表顶部往下滑
    d.swipe(w // 2, int(h * 0.30), w // 2, int(h * 0.70), duration=0.3)
    time.sleep(0.6)
    # 再次尝试找搜索输入框
    el = try_locate(d, SEARCH_INPUT_CANDIDATES, "B_after_pull_down", dump_dir)
    if el:
        return True
    # 再滑一次，有些实现需要滑到底
    d.swipe(w // 2, int(h * 0.30), w // 2, int(h * 0.85), duration=0.3)
    time.sleep(0.6)
    el = try_locate(d, SEARCH_INPUT_CANDIDATES, "B_after_pull_down_2", dump_dir)
    return el is not None


def input_search_and_tap(d: u2.Device, name: str, dump_dir: Path) -> bool:
    """路径 B 后续：输入名字 → 点第一个结果"""
    print(f"\n[Step C] 搜索输入 '{name}'")
    el = try_locate(d, SEARCH_INPUT_CANDIDATES, "C_search_input", dump_dir)
    if not el:
        return False
    el.click()
    time.sleep(0.3)
    try:
        d.clear_text()
    except Exception:
        pass
    d.send_keys(name)
    time.sleep(1.2)

    print(f"\n[Step D] 点击匹配项 '{name}'")
    el = d(text=name)
    if el.exists:
        el.click()
        time.sleep(1.5)
        return True
    el = d(textContains=name)
    if el.exists:
        el.click()
        time.sleep(1.5)
        return True

    xml = d.dump_hierarchy()
    (dump_dir / "D_search_result.xml").write_text(xml, encoding="utf-8")
    print(f"    ✗ 未在搜索结果中找到，UI 已 dump")
    return False


def navigate_to_chat(d: u2.Device, name: str, dump_dir: Path) -> bool:
    """两阶段：先直接点击，失败则下拉搜索"""
    if click_from_list_directly(d, name):
        return True
    if not swipe_down_to_reveal_search(d, dump_dir):
        print("    ✗ 下拉后仍未找到搜索栏，可能需要其他触发方式")
        return False
    return input_search_and_tap(d, name, dump_dir)


def enter_voice_mode(d: u2.Device, dump_dir: Path) -> bool:
    print("\n[Step E] 切换到语音输入模式 (点 🎙️)")
    # 先看是不是已经在语音模式
    if d(resourceId=BUTTON_RESOURCE_ID).exists:
        print("    ✓ 已经在语音模式")
        return True

    el = try_locate(d, MIC_ICON_CANDIDATES, "E_mic_icon", dump_dir)
    if not el:
        return False
    el.click()
    time.sleep(1.0)

    if d(resourceId=BUTTON_RESOURCE_ID).exists:
        print("    ✓ [按住 说话] 已出现")
        return True
    print("    ✗ 点击后按钮仍未出现")
    return False


# ---------- 复用 Spike 2b: 按住 + 播放 ---------- #

def find_cable_input() -> int:
    for i, d in enumerate(sd.query_devices()):
        if d["max_output_channels"] > 0 and "CABLE Input" in d["name"]:
            return i
    raise RuntimeError("找不到 CABLE Input")


def press_hold_release(d: u2.Device, audio: np.ndarray, sr: int,
                       out_dev: int) -> None:
    el = d(resourceId=BUTTON_RESOURCE_ID)
    if not el.exists:
        raise RuntimeError("按住说话按钮不存在")
    b = el.info["bounds"]
    x = (b["left"] + b["right"]) // 2
    y = (b["top"] + b["bottom"]) // 2

    duration_s = len(audio) / sr
    total_hold_ms = PRE_ROLL_MS + int(duration_s * 1000) + POST_ROLL_MS
    print(f"    时序: 按下@({x},{y}) → +{PRE_ROLL_MS}ms 播放 "
          f"→ +{POST_ROLL_MS}ms 松开   共 {total_hold_ms}ms")

    done = threading.Event()

    def _play():
        time.sleep(PRE_ROLL_MS / 1000)
        sd.play(audio, samplerate=sr, device=out_dev, blocking=True)
        done.set()

    t_start = time.perf_counter()
    d.touch.down(x, y)
    thr = threading.Thread(target=_play, daemon=True)
    thr.start()
    thr.join(timeout=duration_s + 5)
    time.sleep(POST_ROLL_MS / 1000)
    d.touch.up(x, y)
    print(f"    ▲ 完成，实际耗时 {time.perf_counter() - t_start:.3f}s")


# ---------- 主 ---------- #

def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python spike3_contact_switch.py <联系人/群名> [wav_path] [--dry-run]")
        return 1

    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    if dry_run:
        args.remove("--dry-run")
    target_name = args[0]
    wav_path = Path(args[1]) if len(args) > 1 else Path("test.wav")

    dump_dir = Path(__file__).parent
    print("=" * 60)
    print(f"  Spike 3: 端到端 (目标={target_name}, dry_run={dry_run})")
    print("=" * 60)

    # 连接
    adb = adbutils.adb
    if not adb.device_list():
        adb.connect(f"127.0.0.1:{MUMU_PORT}", timeout=2.0)
    devs = adb.device_list()
    if not devs:
        print("✗ adb 未连接")
        return 2
    d = u2.connect(devs[0].serial)
    print(f"  ✓ 已连接 {devs[0].serial}   分辨率: "
          f"{d.info['displayWidth']}x{d.info['displayHeight']}")

    input("\n请确保 MuMu 里企微已登录、处于任意界面，按回车开始导航 > ")

    # 步骤链
    go_home(d)
    if not navigate_to_chat(d, target_name, dump_dir):
        return 3
    if not enter_voice_mode(d, dump_dir):
        return 6

    take_screenshot(d, dump_dir / "ready_state.png")

    print("\n" + "=" * 60)
    print("  ✅ 导航链路全部通过")
    print("=" * 60)

    if dry_run:
        print("  🟡 dry-run 模式，跳过发送")
        return 0

    # 发送
    if not wav_path.exists():
        print(f"  ⚠ 音频不存在: {wav_path}，跳过发送")
        return 0
    audio, sr = sf.read(str(wav_path), dtype="float32", always_2d=False)
    if audio.ndim > 1:
        audio = audio.mean(axis=1)
    print(f"\n[Step F] 发送音频 ({len(audio) / sr:.2f}s)")

    for i in range(3, 0, -1):
        print(f"    {i} ...")
        time.sleep(1)

    try:
        press_hold_release(d, audio, sr, find_cable_input())
    except Exception as e:
        print(f"✗ 发送出错: {e}")
        return 7

    print("\n🎉 请检查企微是否发出气泡语音")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
