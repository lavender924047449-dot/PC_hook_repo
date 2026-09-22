"""
全自动右键+菜单验收脚本（无需手动发素材）。

流程：
  1. 打开企微 FTA 聊天
  2. 发送一条测试文字 "val-test-xyz" 到 FTA（作为可见气泡）
  3. 对最底部气泡执行坐标右键（Phase 3 兜底）
  4. 检查"转发"菜单项是否被成功触发
  5. 若成功：打印 [PASS]；若失败：打印 [FAIL] 并输出诊断信息

注意：脚本不会真的转发消息，点击"转发"后会立即按 ESC 关闭弹窗。

用法：
  cd "d:\\Only internship outputs\\Test-Voice"
  python spikes/spike_rightclick_autotest.py

可调参数见脚本底部 LOCATORS 块。
"""
from __future__ import annotations

import sys, time, ctypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from loguru import logger

# ── 可调参数 ──────────────────────────────────────────────────────────────────
from app.pc_wecom.locators import LocatorSet

LOCATORS = LocatorSet(
    chat_left_ratio=0.22,
    bubble_click_x_ratio=0.75,
    input_area_height=80,
    # ── 测试文字气泡模式（val-autotest-xyz 就是最底部消息）────────────────
    # 文字气泡高度约 44px；echo_bubble_height=0, offset=22 => 点击最底部气泡中心
    # 生产模式（图片+echo）应改回：echo_bubble_height=50, offset=120
    echo_bubble_height=0,
    material_bubble_offset=22,
    context_menu_dx=10,
    context_menu_item_height=34,
    context_menu_top_padding=8,
    context_menu_forward_idx=1,  # "转发"在菜单第几项（0 起，默认1=第2项）
)

# ── 初始化导航器 ──────────────────────────────────────────────────────────────
from app.pc_wecom.pc_navigator import BubbleAnchor, PCWeComNavigator, NullBackend

nav = PCWeComNavigator(locators=LOCATORS)

# ── Step 1: 确认企微窗口 ──────────────────────────────────────────────────────
logger.info("[1/5] 连接企微主窗口...")
try:
    nav.ensure_running()
    logger.success("    企微主窗口已连接")
except Exception as e:
    logger.error(f"    FAIL: {e}")
    logger.error("    请先启动并登录 PC 企业微信")
    sys.exit(1)

# ── Step 2: 打开 FTA ──────────────────────────────────────────────────────────
logger.info("[2/5] 打开文件传输助手...")
try:
    nav.open_fta()
    time.sleep(0.8)
    logger.success("    FTA 已打开")
except Exception as e:
    logger.error(f"    FAIL: {e}")
    sys.exit(1)

# ── Step 3: 发送一条测试文字（作为可见气泡）────────────────────────────────
TEST_TEXT = "val-autotest-xyz"
logger.info(f"[3/5] 发送测试文字到 FTA: {TEST_TEXT!r}")
try:
    nav.send_text(TEST_TEXT)
    time.sleep(1.0)  # 等消息出现在聊天列表
    logger.success("    测试文字已发送")
except Exception as e:
    logger.warning(f"    发送文字失败（将继续尝试右键）: {e}")

# ── Step 4: 对最底部气泡执行坐标右键 ─────────────────────────────────────────
# 注意：测试文字是刚发的消息，它就在最底部，echo_bubble_height=0 可能更准
# 但我们先用默认参数，看气泡定位是否 OK
logger.info("[4/5] 对底部气泡执行坐标右键...")

# 构造一个没有有效 fingerprint 的锚点，强制走 Phase 3 坐标兜底
test_anchor = BubbleAnchor(
    material_code=TEST_TEXT,
    fingerprint_snippet="",          # 空→ UIA 匹配必然失败 → 走坐标兜底
    send_time_ms=0,                  # 0→ UIA 时间匹配跳过
    sequence=0,
)

try:
    nav.long_press_bubble(test_anchor)
    logger.success("    右键已执行（见上方阶段日志）")
except Exception as e:
    logger.error(f"    right_click_bubble FAIL: {e}")
    sys.exit(1)

# ── Step 5: 检测"转发"菜单是否出现 ──────────────────────────────────────────
logger.info("[5/5] 尝试点击'转发'菜单项（快速 UIA 探测 + 坐标兜底）...")
time.sleep(0.2)

# 先用 UIA Desktop 根搜索（加 Fast 超时，避免等太久把菜单关掉）
menu_found = False
try:
    from pywinauto import Desktop as _Desktop
    from pywinauto import timings as _timings
    _timings.Timings.fast()
    try:
        desktop = _Desktop(backend="uia")
        for name in ("转发", "Forward"):
            try:
                item = desktop.window(title=name, control_type="MenuItem")
                rect = item.wrapper_object().rectangle()
                item.wrapper_object().click_input()
                logger.success(f"    [UIA Desktop] 找到并点击菜单项 {name!r}  位置={rect}")
                menu_found = True
                break
            except Exception:
                continue
    finally:
        _timings.Timings.defaults()
except Exception as ex:
    logger.debug(f"    [UIA Desktop] 异常: {ex}")

if not menu_found:
    # 尝试主窗口内搜索（同样 Fast 超时）
    try:
        from pywinauto import timings as _timings2
        _timings2.Timings.fast()
        try:
            backend = nav._backend
            if hasattr(backend, '_win') and backend._win is not None:
                item = backend._win.child_window(title="转发", control_type="MenuItem")
                item.wrapper_object().click_input()
                logger.success("    [UIA主窗口] 找到并点击'转发'菜单项")
                menu_found = True
        finally:
            _timings2.Timings.defaults()
    except Exception:
        pass

if menu_found:
    logger.success("=" * 50)
    logger.success("  [PASS] 上下文菜单已弹出且找到'转发'!")
    logger.success("=" * 50)
    # 按 Escape 关闭菜单（不真转发）
    try:
        import win32api, win32con
        win32api.keybd_event(0x1B, 0, 0, 0)   # VK_ESCAPE down
        win32api.keybd_event(0x1B, 0, 2, 0)   # VK_ESCAPE up
    except Exception:
        pass
else:
    # 用坐标兜底点击"转发"（看是否能触发选人弹窗）
    logger.warning("    UIA 未找到'转发'菜单项，尝试坐标点击...")
    try:
        nav.pick_forward_menu()
        logger.success("    [坐标] pick_forward_menu 执行成功（可能已触发选人弹窗）")
        logger.info("    请确认是否弹出「选择联系人」弹窗；若是：[PASS]")
        # 等待用户确认后按 ESC
        time.sleep(2)
        try:
            import win32api
            win32api.keybd_event(0x1B, 0, 0, 0)
            win32api.keybd_event(0x1B, 0, 2, 0)
        except Exception:
            pass
    except Exception as e:
        logger.error(f"    [FAIL] pick_forward_menu 失败: {e}")
        logger.error("")
        logger.error("  诊断建议：")
        logger.error("  1. 确认企微 FTA 聊天为当前活动窗口")
        logger.error("  2. 调整 material_bubble_offset(当前=120), 试 100/150/180")
        logger.error("  3. 检查转发在菜单中的位置, 调整 context_menu_forward_idx")
        logger.error("  4. 查看 runtime/nav_dumps/ 目录中的 UI dump 文件")
        sys.exit(1)

logger.info("")
logger.info("自动测试完成")
