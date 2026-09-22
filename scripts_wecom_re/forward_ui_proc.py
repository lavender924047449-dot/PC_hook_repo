"""
forward_ui_proc.py — 进程 2 (venv Python)
等 Frida hook 就绪后执行 UI 自动化转发
"""
from __future__ import annotations

import sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
from loguru import logger
from app.pc_wecom.locators import LocatorSet
from app.pc_wecom.pc_navigator import BubbleAnchor, PCWeComNavigator

# 此脚本由 capture_forward_unified.py 调用，hook 已就绪
logger.info("[UI] 开始 UI 自动化...")
time.sleep(0.5)

LOCATORS = LocatorSet(
    chat_left_ratio=0.22,
    bubble_click_x_ratio=0.75,
    input_area_height=80,
    echo_bubble_height=0,
    material_bubble_offset=22,
    context_menu_dx=10,
    context_menu_item_height=34,
    context_menu_top_padding=8,
    context_menu_forward_idx=1,
)

nav = PCWeComNavigator(locators=LOCATORS)

try:
    nav.ensure_running()
    logger.success("[UI] 企微已连接")
except Exception as e:
    logger.error(f"[UI] 连接失败: {e}")
    sys.exit(1)

try:
    nav.open_fta()
    time.sleep(1.0)
    logger.success("[UI] FTA 已打开")
except Exception as e:
    logger.error(f"[UI] 打开 FTA 失败: {e}")
    sys.exit(1)

TEST_TEXT = f"fwd-cap-{int(time.time())}"
logger.info(f"[UI] 发测试消息: {TEST_TEXT!r}")
try:
    nav.send_text(TEST_TEXT)
    time.sleep(1.5)
except Exception as e:
    logger.warning(f"[UI] 发消息失败: {e}")

logger.info("[UI] 右键底部气泡...")
test_anchor = BubbleAnchor(
    material_code=TEST_TEXT,
    fingerprint_snippet="",
    send_time_ms=0,
    sequence=0,
)
try:
    nav.long_press_bubble(test_anchor)
    time.sleep(0.5)
    logger.success("[UI] 右键完成")
except Exception as e:
    logger.error(f"[UI] 右键失败: {e}")
    DONE_FLAG.write_text("done-err")
    sys.exit(1)

logger.info("[UI] 点击'转发'...")
try:
    nav.pick_forward_menu()
    time.sleep(1.0)
    logger.success("[UI] 转发菜单已触发!")
except Exception as e:
    logger.error(f"[UI] 点击转发失败: {e}")
    DONE_FLAG.write_text("done-err")
    sys.exit(1)

FORWARD_TARGET = "文件传输助手"
logger.info(f"[UI] 搜索: {FORWARD_TARGET!r}")
try:
    ok = nav.search_and_pick_contact(FORWARD_TARGET)
    logger.success(f"[UI] 联系人选择: {'成功' if ok else '未找到'}")
    time.sleep(0.5)
except Exception as e:
    logger.warning(f"[UI] 搜索联系人异常: {e}")

logger.info("[UI] 确认发送...")
try:
    nav.confirm_send()
    logger.success("[UI] 发送完成!")
except Exception as e:
    logger.warning(f"[UI] 确认发送异常: {e}")

# 写完成 flag
DONE_FLAG.write_text("done-ok")
logger.success(f"[UI] 已写 done flag -> {DONE_FLAG}")
