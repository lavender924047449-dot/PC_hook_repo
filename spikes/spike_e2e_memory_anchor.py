"""
端到端验收脚本：启动完整捕获链路（含内存锚点），等待素材进入 FTA。

用法：
  python spikes/spike_e2e_memory_anchor.py

操作：
  1. 运行此脚本（Ctrl+C 结束）
  2. 在企业微信「文件传输助手」发送一条图片/文件/语音/文本
  3. 观察日志：
     - "素材捕获" 行 → 确认 cache_scanner 工作
     - "内存锚点" 行 → 确认 WeComMemoryReader 找到 send_time_ms
     - "AnchorRecord" 行 → 确认 has_memory_anchor=True
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# ── 路径修正（直接从项目根运行）───────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from loguru import logger

# ── 配置 ──────────────────────────────────────────────────────────────────
try:
    from app.config import get_config
    cfg = get_config()
except Exception as e:
    logger.error(f"加载配置失败: {e}（继续使用默认值）")
    cfg = None

# ── 资产库 ────────────────────────────────────────────────────────────────
from app.messaging.asset_library import AssetLibrary
from app.messaging.cache_scanner import WeComCacheScanner
from app.pc_wecom.bubble_anchor import BubbleAnchorService
from app.pc_wecom.fta_code_echo import FtaCodeEcho

# ── 可选：WeComMemoryReader ───────────────────────────────────────────────
memory_reader = None
try:
    from app.pc_wecom.wecom_memory_reader import WeComMemoryReader
    memory_reader = WeComMemoryReader()
    logger.success(f"WeComMemoryReader 初始化成功 (PID={memory_reader.pid})")
except Exception as e:
    logger.warning(f"WeComMemoryReader 不可用（不影响主流程）: {e}")

# ── 主链路 ────────────────────────────────────────────────────────────────
RUNTIME = ROOT / "runtime"
lib_path = RUNTIME / "asset_library.json"
lib = AssetLibrary(lib_path)
anchor_svc = BubbleAnchorService(lib, memory_reader=memory_reader)
echo = FtaCodeEcho(
    anchor_svc,
    mode="clipboard",           # 不触发真实 Ctrl+V，避免干扰企微
    memory_reader=memory_reader,
)

# 额外订阅：每次捕获后打印 AnchorRecord 详情
def _on_captured(evt):
    code = (evt.entry.material_code or "").strip()
    if not code:
        return
    try:
        # BubbleAnchorService.locate() 直接返回 current 字典
        cur = anchor_svc.locate(code)
        ts_ms = cur.get("send_time_ms", 0)
        seq   = cur.get("sequence", 0)
        mid   = cur.get("wecom_message_id", 0)
        has_anchor = ts_ms > 0 and seq > 0

        logger.info(f"─── AnchorRecord for {code} ───")
        logger.info(f"  bubble_timestamp : {cur.get('bubble_timestamp')}")
        logger.info(f"  send_time_ms     : {ts_ms}  {'✅ 内存锚点' if has_anchor else '❌ 未获取'}")
        logger.info(f"  sequence         : {seq}")
        logger.info(f"  wecom_message_id : {mid}")
        logger.info(f"  has_memory_anchor: {has_anchor}")
    except Exception as ex:
        logger.warning(f"读取 AnchorRecord 失败: {ex}")

scanner = WeComCacheScanner.auto_detect()
scanner.subscribe(echo.on_material_captured)
scanner.subscribe(_on_captured)

# ── 启动 ──────────────────────────────────────────────────────────────────
logger.info("=" * 55)
logger.info("  端到端验收：等待素材进入「文件传输助手」...")
logger.info("  请在企微 FTA 发送 图片/文件/语音/文本")
logger.info("  Ctrl+C 退出")
logger.info("=" * 55)

try:
    import threading
    watcher = threading.Thread(
        target=lambda: scanner.watch_stream(lib, timeout_s=0),
        daemon=True,
        name="cache-watcher",
    )
    watcher.start()
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    logger.info("监听已停止")
