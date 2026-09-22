"""
auto_forward_capture.py
联合脚本：Frida INSERT hook + UI 自动化触发转发，全自动捕获转发 SQL

流程：
1. Frida 附加 + 设置 0x1023810 INSERT hook
2. UI 自动化：打开 FTA → 发测试消息 → 右键 → 转发 → 选联系人 → 发送
3. 捕获 INSERT 事件（转发后数据库写入）
4. 打印结果

测试转发目标: 文件传输助手 (FTA, 安全的自测目标)
"""
from __future__ import annotations

import sys, time, json, threading, subprocess
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

import frida

# 使用项目 venv 中的包
VENV = ROOT / ".venv" / "Lib" / "site-packages"
if str(VENV) not in sys.path:
    sys.path.insert(0, str(VENV))

from loguru import logger
from app.pc_wecom.locators import LocatorSet
from app.pc_wecom.pc_navigator import BubbleAnchor, PCWeComNavigator, NullBackend

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
OUT.mkdir(parents=True, exist_ok=True)

BASELINE_BT0 = {
    0x9052c51, 0x3130178, 0x8ff5bd5, 0x90af838, 0x90b41d2,
    0x90958de, 0x90cc7ed, 0x901b087, 0x90a9f91, 0x90cc49a,
    0x90d17b2, 0x90febaf
}

# ─── Frida 设置 ───────────────────────────────────────────────────────────────
def get_main_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
logger.info(f"[Frida] PID = {pid}")

baseline_str = "[" + ",".join(f"0x{x:x}" for x in sorted(BASELINE_BT0)) + "]"

JS = f"""
'use strict';
var TARGET = ptr(0x1023810);
var BASELINE = {baseline_str};
var BASELINE_SET = {{}};
BASELINE.forEach(function(a){{ BASELINE_SET[a] = 1; }});
var HIT = 0;

function ss(p) {{
    try {{
        if(!p || p.isNull()) return '';
        var s = p.readCString(300);
        return s ? s.slice(0, 250) : '';
    }} catch(e) {{ return ''; }}
}}

Interceptor.attach(TARGET, {{
    onEnter: function(args) {{
        HIT++;
        if (HIT > 100000) return;
        
        var strs = [];
        for (var i = 0; i < 6; i++) strs.push(ss(args[i]));
        
        var isInsert = strs.some(function(s){{
            return s.match(/^(INSERT|REPLACE|insert|replace)/);
        }});
        if (!isInsert) return;
        
        var bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 8)
                       .map(function(a){{return a.toString();}});
        var bt0 = bt.length > 0 ? parseInt(bt[0], 16) : 0;
        var isNew = !BASELINE_SET[bt0];
        
        send({{
            t: 'insert',
            n: HIT,
            strs: strs,
            bt: bt,
            bt0: bt0,
            isNew: isNew,
            tid: this.threadId
        }});
    }}
}});
send({{t: 'ready'}});
"""

insert_events = []
new_events = []
hook_ready_event = threading.Event()

dev = frida.get_local_device()
sess = dev.attach(pid)
sc = sess.create_script(JS)

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    t = p.get("t","")
    if t == "ready":
        logger.success("[Frida] INSERT hook 就绪!")
        hook_ready_event.set()
    elif t == "insert":
        insert_events.append(p)
        strs = p.get("strs", [])
        bt = p.get("bt", [])
        bt0 = p.get("bt0", 0)
        n = p.get("n", 0)
        is_new = p.get("isNew", False)
        sql = next((s for s in strs if s), "")
        mark = "🆕 NEW" if is_new else "   "
        logger.info(f"{mark} INSERT #{n} bt0=0x{bt0:x} | {sql[:80]!r}")
        if is_new:
            new_events.append(p)

sc.on("message", on_msg)
sc.load()

# 等待 hook 就绪
if not hook_ready_event.wait(timeout=5):
    logger.error("Hook 未就绪！")
    sys.exit(1)

# ─── UI 自动化 ────────────────────────────────────────────────────────────────
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

logger.info("[UI] 连接企微...")
try:
    nav.ensure_running()
    logger.success("[UI] 企微已连接")
except Exception as e:
    logger.error(f"[UI] 连接失败: {e}")
    sys.exit(1)

logger.info("[UI] 打开 FTA...")
try:
    nav.open_fta()
    time.sleep(1.0)
except Exception as e:
    logger.error(f"[UI] 打开 FTA 失败: {e}")
    sys.exit(1)

TEST_TEXT = f"forward-capture-{int(time.time())}"
logger.info(f"[UI] 发送测试消息: {TEST_TEXT!r}")
try:
    nav.send_text(TEST_TEXT)
    time.sleep(1.5)
except Exception as e:
    logger.warning(f"[UI] 发送消息失败: {e}")

logger.info("[UI] 右键点击底部气泡...")
test_anchor = BubbleAnchor(
    material_code=TEST_TEXT,
    fingerprint_snippet="",
    send_time_ms=0,
    sequence=0,
)
try:
    nav.long_press_bubble(test_anchor)
    time.sleep(0.5)
except Exception as e:
    logger.error(f"[UI] 右键失败: {e}")
    sys.exit(1)

logger.info("[UI] 点击'转发'...")
try:
    nav.pick_forward_menu()
    time.sleep(1.0)
    logger.success("[UI] 转发菜单已点击!")
except Exception as e:
    logger.error(f"[UI] 点击转发失败: {e}")
    sys.exit(1)

# 选择文件传输助手作为转发目标
FORWARD_TARGET = "文件传输助手"
logger.info(f"[UI] 搜索联系人: {FORWARD_TARGET!r}")
try:
    ok = nav.search_and_pick_contact(FORWARD_TARGET)
    if ok:
        logger.success(f"[UI] 联系人已选择: {FORWARD_TARGET}")
    else:
        logger.warning("[UI] 联系人未找到，尝试继续...")
    time.sleep(0.5)
except Exception as e:
    logger.error(f"[UI] 搜索联系人失败: {e}")

logger.info("[UI] 点击'确认发送'...")
try:
    nav.confirm_send()
    logger.success("[UI] 发送完成!")
except Exception as e:
    logger.error(f"[UI] 确认发送失败: {e}")

# 等待数据库写入
logger.info("[*] 等待 5s 让数据库写入完成...")
time.sleep(5)

# ─── 结果 ────────────────────────────────────────────────────────────────────
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"auto_forward_{ts}.json"
out_f.write_text(json.dumps(insert_events, ensure_ascii=False, indent=2), encoding="utf-8")

logger.info(f"\n{'='*60}")
logger.info(f"总 INSERT 事件: {len(insert_events)}")
logger.info(f"新(非背景)事件: {len(new_events)}")

if new_events:
    logger.success("\n🎯 转发专属 INSERT 已找到！")
    for ev in new_events:
        strs = ev.get("strs", [])
        bt = ev.get("bt", [])
        sql = next((s for s in strs if s), "")
        logger.success(f"  bt[0]=0x{ev['bt0']:x}")
        logger.success(f"  SQL: {sql[:150]!r}")
        logger.success(f"  bt:  {bt[:4]}")
else:
    logger.warning("\n⚠️ 未发现非背景 INSERT（可能 UI 自动化未完成转发）")

logger.info(f"\n结果 -> {out_f}")
