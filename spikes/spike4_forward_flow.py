"""
Spike 4: 文件传输助手 → 长按消息 → 转发 → 选联系人 → 发送

目的（Stage 4.5.0 素材库 Spike）:
    验证"从文件传输助手转发一条已有卡片给指定联系人"整条链路能否用
    UIAutomator 稳定自动化。这决定了 AssetLibrary（小程序/视频号/位置）
    是否可行。

流程:
    企微 (任意界面)
      → 回到消息首页
      → 打开"文件传输助手"聊天
      → 枚举可见消息气泡 (从底部往上编号 0,1,2,...)
      → 长按目标消息 (index_from_bottom)
      → 弹出上下文菜单 → 定位"转发"
      → 点击"转发" → 进入选人界面
      → 搜索目标联系人 → 点击 → 确认发送

每一步都:
    - 打印发现的可疑节点 (bounds/resourceId/text/description/class)
    - dump UI 树到 dump_stepX.xml
    - 关键节点截图 stepX.png

用法:
    # 只探索：长按第 0 条消息 (最底部/最新的一条)，看菜单结构
    python spike4_forward_flow.py --explore

    # 长按第 N 条消息 (从底部数)
    python spike4_forward_flow.py --explore --index 2

    # 完整链路：长按 index=0 消息 → 转发给 "张三"
    python spike4_forward_flow.py --to "张三"

    # 完整链路 + 指定源消息
    python spike4_forward_flow.py --to "张三" --index 2

    # 干跑：走到"选人"界面就停，不真发
    python spike4_forward_flow.py --to "张三" --dry-run

    # 多选群发：一次转发给多个联系人 (B 模式核心)
    python spike4_forward_flow.py --to-many "张三,李四,王五"
    python spike4_forward_flow.py --to-many "张三,李四" --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path

import adbutils
import uiautomator2 as u2


MUMU_PORT = 16384
FTA_NAME = "文件传输助手"   # File Transfer Assistant

# 消息气泡容器的候选定位（企微不同版本可能不同，spike 会实际验证）
# 常见特征：RecyclerView / ListView 里的可点击 item
CHAT_LIST_CANDIDATES = [
    dict(className="androidx.recyclerview.widget.RecyclerView"),
    dict(className="android.support.v7.widget.RecyclerView"),
    dict(className="android.widget.ListView"),
]

# "转发" 菜单项候选
FORWARD_MENU_CANDIDATES = [
    dict(text="转发"),
    dict(textContains="转发"),
    dict(description="转发"),
]

# 选人界面 - 右上角可能的搜索图标 (需要点击后才展开输入框)
CONTACT_SEARCH_ICON_CANDIDATES = [
    dict(resourceId="com.tencent.wework:id/nt8"),
    dict(resourceId="com.tencent.wework:id/nt3"),
    dict(description="搜索"),
    dict(descriptionContains="搜索"),
]

# 展开搜索栏后的输入框
CONTACT_SEARCH_EDIT_CANDIDATES = [
    dict(className="android.widget.EditText"),
]

# 选人界面 - "发送" / "确认" 按钮 (二次弹窗)
# 注意: 弹窗顶上有 "分别发送给:" 这行, 不能用 textContains="发送" 否则误点标题
# 单选弹窗按钮 text = "发送"; 多选弹窗按钮 text = "发送(N)"
SEND_CONFIRM_CANDIDATES = [
    dict(textStartsWith="发送"),      # 匹配 "发送" 或 "发送(2)"，跳过"分别发送给"
    dict(text="确定"),
    dict(text="确认"),
    dict(textStartsWith="确定发送"),
]

# 多选模式切换图标 (选人界面右上角的 ✓)
# 从 screenshot 可见: 右上有两个图标, 左边 🔍 右边 ✓
# nt3 是最右 (bounds [828,36][900,108]) → 大概率是 ✓ (多选)
# nt8 是次右 (bounds [756,36][828,108]) → 大概率是 🔍 (搜索)
MULTISELECT_ICON_CANDIDATES = [
    dict(resourceId="com.tencent.wework:id/nt3"),
    dict(description="多选"),
    dict(descriptionContains="多选"),
]

# 多选完成后底部的"确定(N)/完成/发送"按钮候选
MULTISELECT_DONE_CANDIDATES = [
    dict(resourceId="com.tencent.wework:id/lt5"),
    dict(textStartsWith="确定"),
    dict(textStartsWith="完成"),
    dict(textStartsWith="发送"),
    dict(textContains="确定"),
    dict(textContains="完成"),
    dict(textContains="发送"),
]

HOME_TAB = dict(text="消息")


# ============================================================ #
#                        通用工具                                 #
# ============================================================ #

def dump(d: u2.Device, name: str, out_dir: Path) -> Path:
    p = out_dir / f"dump_{name}.xml"
    p.write_text(d.dump_hierarchy(), encoding="utf-8")
    print(f"    📄 UI dump → {p.name}")
    return p


def shot(d: u2.Device, name: str, out_dir: Path) -> Path:
    p = out_dir / f"shot_{name}.png"
    try:
        d.screenshot(str(p))
        print(f"    📸 截图  → {p.name}")
    except Exception as e:
        print(f"    ✗ 截图失败: {e}")
    return p


def try_locate(d: u2.Device, candidates: list[dict], step: str,
               out_dir: Path) -> u2.UiObject | None:
    for i, sel in enumerate(candidates):
        try:
            el = d(**sel)
            if el.exists:
                print(f"    ✓ 命中 [{i}] {sel}")
                return el
        except Exception as e:
            print(f"    · [{i}] {sel}  ({e})")
    dump(d, f"{step}_MISS", out_dir)
    print(f"    ✗ {step}: 所有候选均未命中")
    return None


def go_home(d: u2.Device) -> None:
    print("\n[A] 回到消息首页")
    for _ in range(5):
        home = d(**HOME_TAB)
        if home.exists:
            if not home.info.get("selected", False):
                home.click()
                time.sleep(0.5)
            print("    ✓ 已在消息列表")
            return
        d.press("back")
        time.sleep(0.3)
    print("    ⚠ 未确认在消息列表，继续")


def open_chat(d: u2.Device, name: str, out_dir: Path) -> bool:
    """打开指定聊天。直接点或下拉搜。"""
    print(f"\n[B] 打开聊天 '{name}'")
    # 直点
    el = d(text=name)
    if not el.exists:
        el = d(textContains=name)
    if el.exists:
        el.click()
        time.sleep(1.5)
        print("    ✓ 从列表直接点开")
        return True

    # 下拉搜索
    print("    · 列表未见，下拉调出搜索栏")
    w = d.info["displayWidth"]
    h = d.info["displayHeight"]
    for factor in (0.7, 0.85):
        d.swipe(w // 2, int(h * 0.3), w // 2, int(h * factor), duration=0.3)
        time.sleep(0.6)
        if d(className="android.widget.EditText").exists:
            break
    edit = d(className="android.widget.EditText")
    if not edit.exists:
        dump(d, "B_no_search", out_dir)
        print("    ✗ 未找到搜索框")
        return False
    edit.click()
    time.sleep(0.3)
    try:
        d.clear_text()
    except Exception:
        pass
    d.send_keys(name)
    time.sleep(1.2)

    for sel in (dict(text=name), dict(textContains=name)):
        el = d(**sel)
        if el.exists:
            el.click()
            time.sleep(1.5)
            print(f"    ✓ 已点击搜索结果 {sel}")
            return True
    dump(d, "B_no_result", out_dir)
    print("    ✗ 搜索无结果")
    return False


# ============================================================ #
#                    核心：消息枚举 & 长按                         #
# ============================================================ #

def enumerate_bubbles(d: u2.Device, out_dir: Path) -> list[dict]:
    """
    枚举当前聊天窗口中可见的"消息气泡"节点。
    我们不知道确切的 resourceId，所以采用启发式：
        - 找到 chat list 容器
        - 遍历它的直接可点击/可长按子节点
        - 记录 bounds + text + resourceId + class
    返回从上到下的 bubble 列表 (index 0 = 最上方)。
    """
    print("\n[C] 枚举消息气泡")
    container = try_locate(d, CHAT_LIST_CANDIDATES, "C_list", out_dir)
    if not container:
        return []

    # 用 xml 解析，抓 RecyclerView 内容里的 clickable/long-clickable 节点
    import xml.etree.ElementTree as ET
    xml_str = d.dump_hierarchy()
    root = ET.fromstring(xml_str)

    bubbles: list[dict] = []
    # 找 RecyclerView 节点
    for node in root.iter("node"):
        cls = node.attrib.get("class", "")
        if "RecyclerView" not in cls and "ListView" not in cls:
            continue
        # 找它下面 depth<=3 的 long-clickable=true 节点
        for child in node.iter("node"):
            long_c = child.attrib.get("long-clickable", "false") == "true"
            if not long_c:
                continue
            bounds_str = child.attrib.get("bounds", "")
            m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
            if not m:
                continue
            l, t, r, b = map(int, m.groups())
            if (r - l) < 40 or (b - t) < 40:      # 太小的忽略
                continue
            bubbles.append({
                "bounds": (l, t, r, b),
                "cx": (l + r) // 2,
                "cy": (t + b) // 2,
                "class": child.attrib.get("class", ""),
                "resource-id": child.attrib.get("resource-id", ""),
                "text": child.attrib.get("text", ""),
                "content-desc": child.attrib.get("content-desc", ""),
            })
        break   # 只看第一个匹配的容器

    # 按 y 排序，从上到下
    bubbles.sort(key=lambda x: x["cy"])
    print(f"    ✓ 发现 {len(bubbles)} 个 long-clickable 气泡节点")
    for i, b in enumerate(bubbles):
        print(f"      #{i}  y={b['cy']:>4}  "
              f"rid='{b['resource-id']}'  "
              f"cls='{b['class'].split('.')[-1]}'  "
              f"text='{b['text'][:20]}'  "
              f"desc='{b['content-desc'][:20]}'")
    return bubbles


def long_press_bubble(d: u2.Device, bubbles: list[dict],
                      index_from_bottom: int, out_dir: Path) -> bool:
    """长按第 N 条消息 (0 = 最新/最底部)"""
    if not bubbles:
        print("    ✗ 无气泡可长按")
        return False
    if index_from_bottom >= len(bubbles):
        print(f"    ✗ index={index_from_bottom} 超出范围 (共 {len(bubbles)} 条)")
        return False
    # bubbles 是从上到下，index_from_bottom=0 就是最后一个
    target = bubbles[-1 - index_from_bottom]
    x, y = target["cx"], target["cy"]
    print(f"\n[D] 长按气泡 index_from_bottom={index_from_bottom} @({x},{y})")
    print(f"    目标: {target}")
    shot(d, f"D_before_longpress", out_dir)
    # uiautomator2: long_click 默认 500ms，够触发菜单
    d.long_click(x, y, duration=0.8)
    time.sleep(1.0)
    shot(d, f"D_after_longpress", out_dir)
    dump(d, f"D_context_menu", out_dir)
    return True


def find_and_tap_forward(d: u2.Device, out_dir: Path) -> bool:
    """在弹出菜单里找到"转发"并点击"""
    print("\n[E] 定位并点击 '转发'")
    el = try_locate(d, FORWARD_MENU_CANDIDATES, "E_forward", out_dir)
    if not el:
        return False
    el.click()
    time.sleep(1.2)
    shot(d, "E_after_forward_click", out_dir)
    dump(d, "E_forward_flow", out_dir)
    return True


def _click_contact_row(d: u2.Device, contact: str) -> bool:
    """
    点击"选择聊天"列表里 text=contact 的行。
    该 TextView 本身通常 clickable=false，但 uiautomator2 会按 bounds 中心 tap，
    ListView item 会消费到父行的点击事件。
    """
    for sel in (dict(text=contact), dict(textContains=contact)):
        el = d(**sel)
        if el.exists:
            el.click()
            time.sleep(1.0)
            print(f"    ✓ 命中 {sel}")
            return True
    return False


def search_and_pick_contact(d: u2.Device, contact: str,
                            out_dir: Path) -> bool:
    """
    "选择聊天"界面 → 定位并点击目标联系人。
    策略:
      1) 先在"最近聊天" ListView 里直接匹配文字点击
      2) 若不在最近列表，点顶栏搜索图标 → 展开输入框 → 输入 → 点结果
    """
    print(f"\n[F] 选择联系人 '{contact}'")

    # ---- 策略 1: 最近聊天列表直点 ----
    if _click_contact_row(d, contact):
        shot(d, "F_after_pick", out_dir)
        dump(d, "F_confirm_dialog", out_dir)
        return True

    # ---- 策略 2: 打开顶栏搜索 ----
    print("    · 最近列表未见，尝试打开搜索栏")
    for i, sel in enumerate(CONTACT_SEARCH_ICON_CANDIDATES):
        icon = d(**sel)
        if not icon.exists:
            continue
        print(f"    · 尝试点击搜索图标候选 [{i}] {sel}")
        icon.click()
        time.sleep(0.8)
        edit = try_locate(d, CONTACT_SEARCH_EDIT_CANDIDATES,
                          f"F_edit_after_{i}", out_dir)
        if not edit:
            # 这个图标不是搜索，退回上一屏再试下一个
            d.press("back")
            time.sleep(0.5)
            continue

        # 输入并挑结果
        edit.click()
        time.sleep(0.3)
        try:
            d.clear_text()
        except Exception:
            pass
        d.send_keys(contact)
        time.sleep(1.2)
        dump(d, "F_search_result", out_dir)
        if _click_contact_row(d, contact):
            shot(d, "F_after_pick", out_dir)
            dump(d, "F_confirm_dialog", out_dir)
            return True
        print("    ✗ 搜索后仍未找到")
        return False

    dump(d, "F_no_search_icon", out_dir)
    print("    ✗ 既不在最近列表，也找不到搜索入口")
    return False


def multi_select_and_pick(d: u2.Device, contacts: list[str],
                          out_dir: Path) -> bool:
    """
    进入多选模式 → 逐个勾选 contacts → 点底部"完成/发送"
    (仅到底部按钮为止；最后的二次确认弹窗由 confirm_send 处理)
    """
    print(f"\n[F] 多选群发目标: {contacts}")

    # 1) 切多选
    icon = try_locate(d, MULTISELECT_ICON_CANDIDATES,
                      "F1_multiselect_icon", out_dir)
    if not icon:
        print("    ✗ 未找到多选切换图标")
        return False
    icon.click()
    time.sleep(0.8)
    shot(d, "F1_after_multiselect", out_dir)
    dump(d, "F1_multiselect_mode", out_dir)

    # 2) 逐个点击目标 (在最近列表里)
    hit_count = 0
    missing: list[str] = []
    for c in contacts:
        el = d(text=c)
        if not el.exists:
            el = d(textContains=c)
        if el.exists:
            el.click()
            time.sleep(0.4)
            print(f"    ✓ 勾选 '{c}'")
            hit_count += 1
        else:
            # 试搜索
            print(f"    · '{c}' 不在最近列表，尝试搜索")
            searched = _multiselect_search_and_tick(d, c, out_dir)
            if searched:
                hit_count += 1
            else:
                missing.append(c)

    print(f"    共勾选 {hit_count}/{len(contacts)}")
    if missing:
        print(f"    ⚠ 未勾选: {missing}")
    if hit_count == 0:
        dump(d, "F2_no_hits", out_dir)
        return False

    shot(d, "F2_after_all_ticked", out_dir)
    dump(d, "F2_all_ticked", out_dir)

    # 3) 底部"完成/发送(N)"
    print("    · 点击底部完成/发送")
    done = try_locate(d, MULTISELECT_DONE_CANDIDATES,
                      "F3_done_btn", out_dir)
    if not done:
        return False
    done.click()
    time.sleep(1.2)
    shot(d, "F3_after_done", out_dir)
    dump(d, "F3_confirm_dialog", out_dir)
    return True


def _multiselect_search_and_tick(d: u2.Device, contact: str,
                                 out_dir: Path) -> bool:
    """多选模式下，某个联系人不在最近列表 → 通过搜索勾选"""
    # 找搜索图标 (nt8) 或已存在的 EditText
    edit = d(className="android.widget.EditText")
    if not edit.exists:
        for sel in (dict(resourceId="com.tencent.wework:id/nt8"),
                    dict(description="搜索")):
            icon = d(**sel)
            if icon.exists:
                icon.click()
                time.sleep(0.6)
                break
        edit = d(className="android.widget.EditText")
    if not edit.exists:
        return False
    edit.click()
    time.sleep(0.3)
    try:
        d.clear_text()
    except Exception:
        pass
    d.send_keys(contact)
    time.sleep(1.0)
    for sel in (dict(text=contact), dict(textContains=contact)):
        el = d(**sel)
        if el.exists:
            el.click()
            time.sleep(0.5)
            # 搜索勾选后, 通常会退出搜索框回到列表, 或需 back
            print(f"    ✓ 搜索勾选 '{contact}'")
            return True
    return False


def confirm_send(d: u2.Device, out_dir: Path) -> bool:
    """确认发送 (通常有一个二次确认弹窗)"""
    print("\n[G] 确认发送")
    el = try_locate(d, SEND_CONFIRM_CANDIDATES, "G_confirm", out_dir)
    if not el:
        # 有些版本直接选人=发送，没有二次确认
        print("    · 未见二次确认按钮，可能已直接发送")
        return True
    el.click()
    time.sleep(1.5)
    shot(d, "G_after_send", out_dir)
    return True


# ============================================================ #
#                            主流程                              #
# ============================================================ #

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", help="转发目标联系人/群名 (单选)")
    ap.add_argument("--to-many", dest="to_many",
                    help="多选转发, 逗号分隔多个联系人 (B 模式)")
    ap.add_argument("--index", type=int, default=0,
                    help="要长按的消息在气泡列表中的位置 "
                         "(从底部数, 0=最新, 默认 0)")
    ap.add_argument("--explore", action="store_true",
                    help="只到 '长按+看菜单' 就停 (不需要 --to)")
    ap.add_argument("--dry-run", action="store_true",
                    help="走到 '选中联系人' 就停，不点确认发送")
    args = ap.parse_args()

    if not args.explore and not args.to and not args.to_many:
        print("必须指定 --to / --to-many / --explore 之一")
        return 1
    if args.to and args.to_many:
        print("--to 和 --to-many 不能同时用")
        return 1

    contacts_many: list[str] = []
    if args.to_many:
        contacts_many = [c.strip() for c in args.to_many.split(",")
                         if c.strip()]

    out_dir = Path(__file__).parent / "spike4_dumps"
    out_dir.mkdir(exist_ok=True)
    print("=" * 60)
    print(f"  Spike 4: forward flow   explore={args.explore}  "
          f"to={args.to}  to_many={contacts_many}  "
          f"index={args.index}  dry={args.dry_run}")
    print(f"  dumps → {out_dir}")
    print("=" * 60)

    # ---- 连接 ----
    adb = adbutils.adb
    if not adb.device_list():
        adb.connect(f"127.0.0.1:{MUMU_PORT}", timeout=2.0)
    devs = adb.device_list()
    if not devs:
        print("✗ adb 未连接")
        return 2
    d = u2.connect(devs[0].serial)
    print(f"  ✓ 已连接 {devs[0].serial}   "
          f"{d.info['displayWidth']}x{d.info['displayHeight']}")

    input("\n请确保 MuMu 里企微已登录、且'文件传输助手'里已有你要转发的"
          "小程序/视频号/位置卡片。按回车开始 > ")

    # ---- Step 链 ----
    go_home(d)
    if not open_chat(d, FTA_NAME, out_dir):
        print("✗ 打开文件传输助手失败")
        return 3
    shot(d, "B_in_fta", out_dir)

    bubbles = enumerate_bubbles(d, out_dir)
    if not bubbles:
        print("✗ 枚举气泡失败，请检查 dump_C_list_MISS.xml")
        return 4

    if not long_press_bubble(d, bubbles, args.index, out_dir):
        return 5

    if not find_and_tap_forward(d, out_dir):
        print("  ⚠ 未找到 '转发'，长按可能没弹菜单；"
              "查看 dump_D_context_menu.xml 手工分析")
        return 6

    if args.explore:
        print("\n" + "=" * 60)
        print("  ✅ Explore 完成：长按 + 转发菜单可用")
        print("     下一步分析 dump_E_forward_flow.xml 看选人界面结构")
        print("=" * 60)
        return 0

    # ---- 单选路径 ----
    if args.to:
        if not search_and_pick_contact(d, args.to, out_dir):
            return 7
        if args.dry_run:
            print("\n" + "=" * 60)
            print("  🟡 dry-run 完成 (单选)，已选中目标，未点确认发送")
            print("=" * 60)
            return 0
        if not confirm_send(d, out_dir):
            return 8
        print("\n" + "=" * 60)
        print(f"  🎉 单选全链路通过！请检查 '{args.to}' 是否收到卡片")
        print("=" * 60)
        return 0

    # ---- 多选路径 (B 模式) ----
    if not multi_select_and_pick(d, contacts_many, out_dir):
        return 7
    if args.dry_run:
        print("\n" + "=" * 60)
        print(f"  🟡 dry-run 完成 (多选)，已勾选并到二次确认，未点发送")
        print("=" * 60)
        return 0
    if not confirm_send(d, out_dir):
        return 8
    print("\n" + "=" * 60)
    print(f"  🎉 多选群发通过！请检查 {contacts_many} 是否都收到")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
