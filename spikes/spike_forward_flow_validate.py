"""
端到端转发流程验收脚本（人工辅助）。

目的：
  验证三阶段气泡定位 + click_menu 坐标兜底能否在真实企微 FTA 场景中
  成功触发"转发"上下文菜单，并打印每个阶段的诊断信息。

用法（企微已登录、FTA 聊天已打开）：
  cd "d:\\Only internship outputs\\Test-Voice"
  python spikes/spike_forward_flow_validate.py

交互步骤：
  1. 脚本启动后，先向 FTA 发送一张图片（约 2 秒内）
  2. 脚本会捕获素材、回写编码、获取内存锚点
  3. 提示 "按 Enter 继续执行转发"  → 回车
  4. 脚本执行 long_press_bubble → pick_forward_menu
  5. 若菜单打开，控制台打印 [SUCCESS]；否则打印 [FAIL] 并写 UI dump
  6. 手动 Ctrl+C 中止（不会真正发送给任何人）

调整参数：
  若坐标点击偏移，在脚本底部修改 LocatorSet 参数
  material_bubble_offset / echo_bubble_height / context_menu_forward_idx 等
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from loguru import logger

# ── 加载链路 ──────────────────────────────────────────────────────────────────
from app.messaging.asset_library import AssetLibrary
from app.messaging.cache_scanner import WeComCacheScanner
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.fta_code_echo import FtaCodeEcho
from app.pc_wecom.locators import LocatorSet
from app.pc_wecom.pc_navigator import BubbleAnchor, PCWeComNavigator

# ── 可调参数（若坐标不准请先修改这里）────────────────────────────────────────
LOCATORS = LocatorSet(
    # 气泡定位（基于实测窗口 986×658，可按实际调整）
    chat_left_ratio=0.22,         # 聊天区域左边界（窗口宽度比 ≈ 22%）
    bubble_click_x_ratio=0.75,    # 气泡横向点击位置（自己发的消息在右侧）
    input_area_height=80,         # 输入框高度 px
    echo_bubble_height=50,        # echo 文本气泡高度 px
    #
    # ★ 核心调整参数：从 echo 气泡上边界再向上偏移多少 px 到达素材气泡中心
    #   offset=120 → 对应窗口 y≈536（实测 986x658 窗口）
    #   若右键空白 → 减小 offset；若右键到时间标签/更上方 → 增大 offset
    material_bubble_offset=120,
    # 上下文菜单（企微 FTA 图片/文件气泡典型顺序：收藏0、转发1、复制2…）
    context_menu_dx=10,           # 菜单相对右键点水平偏移
    context_menu_item_height=34,  # 每个菜单项高度 px
    context_menu_top_padding=8,   # 菜单顶部内边距 px
    context_menu_forward_idx=1,   # "转发"在菜单中的索引（默认第2项=index 1）
)

RUNTIME = ROOT / "runtime"
lib_path = RUNTIME / "asset_library.json"

# ── 初始化内存读取器（可选）──────────────────────────────────────────────────
memory_reader = None
try:
    from app.pc_wecom.wecom_memory_reader import WeComMemoryReader
    memory_reader = WeComMemoryReader()
    logger.success(f"WeComMemoryReader OK (PID={memory_reader.pid})")
except Exception as e:
    logger.warning(f"WeComMemoryReader 不可用: {e}")

# ── 捕获 + echo 链路 ──────────────────────────────────────────────────────────
lib = AssetLibrary(lib_path)
anchor_svc = BubbleAnchorService(lib, memory_reader=memory_reader)
echo = FtaCodeEcho(
    anchor_svc,
    mode="paste_if_focused",
    memory_reader=memory_reader,
)

captured_codes: list[str] = []

def _on_captured(evt):
    code = (evt.entry.material_code or "").strip()
    if code:
        captured_codes.append(code)
        logger.info(f"✅ 素材捕获: {code}")

scanner = WeComCacheScanner.auto_detect()
scanner.subscribe(echo.on_material_captured)
scanner.subscribe(_on_captured)

import threading
watcher = threading.Thread(
    target=lambda: scanner.watch_stream(lib, timeout_s=0),
    daemon=True,
    name="cache-watcher",
)
watcher.start()

# ── 等待用户发素材 ────────────────────────────────────────────────────────────
logger.info("=" * 55)
logger.info("  请在企微 FTA 发送一张图片或文件")
logger.info("  等待捕获后按 Enter 执行转发验证...")
logger.info("=" * 55)

try:
    input()  # 等用户按 Enter
except (EOFError, KeyboardInterrupt):
    logger.warning("已中止")
    sys.exit(0)

if not captured_codes:
    logger.error("未捕获到任何素材，请先向 FTA 发素材再按 Enter")
    sys.exit(1)

code = captured_codes[-1]
logger.info(f"  使用素材编码: {code}")

# 等待异步内存扫描完成（最多 30s）
logger.info("  等待内存锚点扫描（最多 30s）...")
for i in range(30):
    anchor = anchor_svc.locate(code)
    if anchor.get("send_time_ms", 0) > 0 and anchor.get("sequence", 0) > 0:
        logger.success(f"  内存锚点已就绪: send_time_ms={anchor['send_time_ms']}")
        break
    time.sleep(1)
else:
    logger.warning("  内存锚点未就绪（将用近似时间戳兜底）")
    anchor = anchor_svc.locate(code)

# ── 构造 BubbleAnchor 并执行转发链路 ─────────────────────────────────────────
nav = PCWeComNavigator(locators=LOCATORS)

bubble = BubbleAnchor(
    material_code=code,
    fingerprint_snippet=anchor.get("fingerprint_snippet"),
    bubble_timestamp=anchor.get("bubble_timestamp"),
    send_time_ms=anchor.get("send_time_ms", 0),
    sequence=anchor.get("sequence", 0),
    wecom_message_id=anchor.get("wecom_message_id", 0),
)

logger.info("")
logger.info("── [Step 1] ensure_running + open_fta ──")
try:
    nav.ensure_running()
    nav.open_fta()
    logger.success("  FTA 已打开")
except Exception as e:
    logger.error(f"  FAIL: {e}")
    sys.exit(1)

logger.info("── [Step 2] long_press_bubble（右键气泡）──")
try:
    nav.long_press_bubble(bubble)
    logger.success("  右键已发送（见日志中的阶段标记）")
except Exception as e:
    logger.error(f"  FAIL: {e}")
    sys.exit(1)

logger.info("── [Step 3] pick_forward_menu ──")
logger.info("  若菜单已弹出，脚本会尝试点击转发...")
try:
    nav.pick_forward_menu()
    logger.success("  [SUCCESS] 转发菜单点击成功!")
    logger.info("  选人弹窗已打开，请手动关闭（勿真正转发）")
except Exception as e:
    logger.error(f"  [FAIL] 转发菜单点击失败: {e}")
    logger.info("  → 请查看 UI dump 文件，调整 LocatorSet 参数后重试")
    sys.exit(1)

logger.info("")
logger.info("=" * 55)
logger.info("  验收完成，请手动关闭选人弹窗（按 ESC）")
logger.info("=" * 55)
