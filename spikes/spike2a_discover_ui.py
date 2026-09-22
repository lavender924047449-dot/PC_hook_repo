"""
Spike 2a: 连接 MuMu + 抓 UI 树 + 定位"按住说话"按钮

目标：
  1) 通过 adb 连接 MuMu 模拟器
  2) 初始化 uiautomator2 (自动 push atx-agent 到设备)
  3) 让用户手动切到企微语音输入模式
  4) dump 一份完整 UI hierarchy 存为 xml (便于分析)
  5) 尝试用关键字匹配定位"按住说话"按钮，打印其属性 & 坐标

产出：
  - ui_dump.xml            : 完整 UI 树，供后续分析
  - button_info.txt        : 定位到的按钮信息 (resourceId/bounds/text)

用法：
  python spike2a_discover_ui.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import adbutils
import uiautomator2 as u2


# ---------- MuMu 常见 adb 端口 ---------- #
MUMU_PORTS = [
    16384,   # MuMu Pro 12 默认
    16416, 16448, 16480,  # MuMu Pro 12 多开时递增
    7555,    # MuMu 6 (旧版)
    5555,    # 通用默认
]

BUTTON_KEYWORDS = [
    "按住 说话", "按住说话",
    "Hold to Talk", "Hold to talk",
    "按住讲话",
]


def connect_mumu() -> adbutils.AdbDevice:
    """自动扫描并连接 MuMu"""
    print("== 步骤 1：连接 MuMu adb ==")
    adb = adbutils.adb

    # 先看看已连接的设备
    existing = adb.device_list()
    if existing:
        print(f"  发现已连接设备: {[d.serial for d in existing]}")
        return existing[0]

    # 依次尝试常见端口
    for port in MUMU_PORTS:
        addr = f"127.0.0.1:{port}"
        print(f"  尝试 connect {addr} ...", end=" ")
        try:
            r = adb.connect(addr, timeout=2.0)
            if "connected" in r.lower() or "already" in r.lower():
                print("✓")
                # 验证一下设备真的在
                for d in adb.device_list():
                    if d.serial == addr:
                        return d
            else:
                print(f"× ({r})")
        except Exception as e:
            print(f"× ({e})")

    raise RuntimeError(
        "未能连接 MuMu adb。请检查：\n"
        "  - MuMu 是否已启动并进入 Android 桌面\n"
        "  - MuMu 设置 → 其他 → 开启 'Root 权限' 和 'adb 调试'\n"
        "  - 或手动在 PowerShell 里跑: adb devices"
    )


def wait_for_wecom(d: u2.Device, timeout: float = 60) -> None:
    """提示用户手动切到企微语音模式"""
    print("\n== 步骤 2：请在 MuMu 里操作 ==")
    print("  1) 打开企业微信")
    print("  2) 打开一个测试聊天窗口")
    print("  3) 点 🎙️ 图标切换到语音输入模式（能看到 [按住 说话] 按钮）")
    print("  4) 保持这个界面，不要离开")
    input("\n  完成后按回车继续 > ")

    info = d.info
    print(f"  当前前台应用: {info.get('currentPackageName', '?')}")


def dump_ui(d: u2.Device, out_dir: Path) -> Path:
    """dump UI hierarchy 存 xml"""
    print("\n== 步骤 3：抓取 UI 树 ==")
    xml = d.dump_hierarchy()
    out_file = out_dir / "ui_dump.xml"
    out_file.write_text(xml, encoding="utf-8")
    print(f"  ✓ 已保存: {out_file}  ({len(xml)} 字节)")
    return out_file


def find_button(d: u2.Device, out_dir: Path) -> bool:
    """尝试多种方式定位按钮"""
    print("\n== 步骤 4：定位 '按住说话' 按钮 ==")

    found = []

    # 方法 1: 精确 text 匹配
    for kw in BUTTON_KEYWORDS:
        el = d(text=kw)
        if el.exists:
            found.append(("text", kw, el))
            print(f"  ✓ text='{kw}' 命中")
            break

    # 方法 2: 模糊 textContains
    if not found:
        for kw in ["按住", "说话", "Hold", "Talk"]:
            el = d(textContains=kw)
            if el.exists:
                found.append(("textContains", kw, el))
                print(f"  ✓ textContains='{kw}' 命中")
                break

    # 方法 3: description 属性
    if not found:
        for kw in BUTTON_KEYWORDS:
            el = d(description=kw)
            if el.exists:
                found.append(("description", kw, el))
                print(f"  ✓ description='{kw}' 命中")
                break

    if not found:
        print("  ✗ 三种方式都没找到按钮")
        print("    请打开 ui_dump.xml 手工搜索 '按住' / '说话' 字样")
        return False

    method, kw, el = found[0]
    info = el.info
    bounds = info.get("bounds", {})
    cx = (bounds.get("left", 0) + bounds.get("right", 0)) // 2
    cy = (bounds.get("top", 0) + bounds.get("bottom", 0)) // 2

    lines = [
        f"定位方法: {method}='{kw}'",
        f"resourceId: {info.get('resourceName', '')}",
        f"class:      {info.get('className', '')}",
        f"text:       {info.get('text', '')}",
        f"desc:       {info.get('contentDescription', '')}",
        f"bounds:     {bounds}",
        f"center:     ({cx}, {cy})",
        f"clickable:  {info.get('clickable', False)}",
        f"longClick:  {info.get('longClickable', False)}",
    ]
    text = "\n".join(lines)
    print("\n" + text)

    (out_dir / "button_info.txt").write_text(text, encoding="utf-8")
    print(f"\n  ✓ 已保存: button_info.txt")
    return True


def main() -> int:
    out_dir = Path(__file__).parent
    print("=" * 60)
    print("  Spike 2a: 连接 MuMu + 抓 UI + 定位按钮")
    print("=" * 60)

    # 1) 连接 adb
    try:
        dev = connect_mumu()
        print(f"  ✓ 已连接: {dev.serial}")
        # 打印设备基本信息
        try:
            model = dev.shell("getprop ro.product.model").strip()
            sdk = dev.shell("getprop ro.build.version.sdk").strip()
            print(f"    型号: {model}    Android SDK: {sdk}")
        except Exception:
            pass
    except Exception as e:
        print(f"✗ {e}")
        return 1

    # 2) 初始化 uiautomator2
    print("\n== 初始化 uiautomator2 (首次会 push atx-agent 到设备) ==")
    try:
        d = u2.connect(dev.serial)
        info = d.info
        print(f"  ✓ 设备就绪  分辨率: {info.get('displayWidth')}x{info.get('displayHeight')}")
    except Exception as e:
        print(f"✗ uiautomator2 初始化失败: {e}")
        print("  提示：如果卡在这里，可能是设备端 atx-agent 未启动")
        print("        试试: python -m uiautomator2 init")
        return 2

    # 3) 等待用户切到企微
    wait_for_wecom(d, timeout=120)

    # 4) dump UI
    xml_path = dump_ui(d, out_dir)

    # 5) 找按钮
    ok = find_button(d, out_dir)

    print("\n" + "=" * 60)
    if ok:
        print("  🟢 Spike 2a 通过！按钮已定位")
        print("  下一步：Spike 2b 全自动按住 + 播放音频")
    else:
        print("  🟡 UI dump 已保存，但按钮未自动匹配到")
        print("  请把 ui_dump.xml 发给我，我人肉分析定位规则")
    print("=" * 60)
    return 0 if ok else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
