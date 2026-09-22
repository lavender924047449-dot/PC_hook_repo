"""
capture_now.py — venv Python (frida + loguru + pywinauto 都有)
完整自动化：Hook + 自动触发转发（10分钟窗口）
"""
from __future__ import annotations
import sys, time, json, threading, subprocess
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

import frida
from loguru import logger
from app.pc_wecom.locators import LocatorSet
from app.pc_wecom.pc_navigator import BubbleAnchor, PCWeComNavigator

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
OUT.mkdir(parents=True, exist_ok=True)

BASELINE_BT0 = {
    0x9052c51, 0x3130178, 0x8ff5bd5, 0x90af838, 0x90b41d2,
    0x90958de, 0x90cc7ed, 0x901b087, 0x90a9f91, 0x90cc49a,
    0x90d17b2, 0x90febaf
}

def get_pid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l:
            return int(l.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_pid()
logger.info(f"PID={pid}")
bl_str = "[" + ",".join(f"0x{x:x}" for x in sorted(BASELINE_BT0)) + "]"

JS = f"""
'use strict';
var T=ptr(0x1023810),HIT=0,BASELINE={bl_str},BS={{}};
BASELINE.forEach(function(a){{BS[a]=1;}});
function ss(p){{try{{if(!p||p.isNull())return"";var s=p.readCString(300);return s?s.slice(0,250):""}}catch(e){{return""}}}}
Interceptor.attach(T,{{onEnter:function(args){{
    HIT++;if(HIT>200000)return;
    var strs=[];for(var i=0;i<6;i++)strs.push(ss(args[i]));
    var ins=strs.some(function(s){{return s.match(/^(INSERT|REPLACE|insert|replace)/);}});
    if(!ins)return;
    var bt=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,8).map(function(a){{return a.toString();}});
    var bt0=bt.length>0?parseInt(bt[0],16):0;
    send({{t:"i",n:HIT,strs:strs,bt:bt,bt0:bt0,isNew:!BS[bt0],tid:this.threadId}});
}}}});
send({{t:"r"}});
"""

events = []
new_events = []
hook_ready = threading.Event()

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    if p.get("t") == "r":
        logger.success("[Frida] Hook READY!")
        hook_ready.set()
    elif p.get("t") == "i":
        events.append(p)
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

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()

if not hook_ready.wait(timeout=5):
    logger.error("Hook 未就绪!")
    sys.exit(1)

# ─── 自动化触发转发 ──────────────────────────────────────────────────────────
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
    logger.warning("[UI] 请手动在企微中执行转发 (10分钟窗口)...")
    time.sleep(600)
    _save_and_exit()

def _save():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    f = OUT / f"capture_now_{ts}.json"
    f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"INSERT={len(events)}, NEW={len(new_events)} -> {f}")
    if new_events:
        logger.success("🎯 转发 INSERT 已捕获！")
        for ev in new_events:
            sql = next((s for s in ev.get("strs",[]) if s), "")
            logger.success(f"  bt0=0x{ev['bt0']:x} | {sql[:120]!r}")
            logger.success(f"  bt={ev.get('bt',[])[:4]}")

logger.info("[UI] 打开 FTA...")
try:
    nav.open_fta()
    time.sleep(1.5)
    logger.success("[UI] FTA 已打开")
except Exception as e:
    logger.error(f"[UI] 打开 FTA 失败: {e}")

TEST_TEXT = f"fwd-{int(time.time())}"
logger.info(f"[UI] 发测试消息: {TEST_TEXT!r}")
try:
    nav.send_text(TEST_TEXT)
    time.sleep(2.0)
    logger.success("[UI] 消息已发")
except Exception as e:
    logger.warning(f"[UI] 发消息失败 ({e})，直接右键底部气泡")

logger.info("[UI] 右键底部气泡...")
test_anchor = BubbleAnchor(
    material_code=TEST_TEXT,
    fingerprint_snippet="",
    send_time_ms=0,
    sequence=0,
)
try:
    nav.long_press_bubble(test_anchor)
    time.sleep(0.6)
    logger.success("[UI] 右键完成")
except Exception as e:
    logger.error(f"[UI] 右键失败: {e}")
    _save()
    sys.exit(1)

logger.info("[UI] 点击'转发'...")
try:
    nav.pick_forward_menu()
    time.sleep(1.2)
    logger.success("[UI] 转发菜单已触发!")
except Exception as e:
    logger.error(f"[UI] 点击转发失败: {e}")
    _save()
    sys.exit(1)

logger.info("[UI] 搜索联系人: 文件传输助手")
try:
    ok = nav.search_and_pick_contact("文件传输助手")
    logger.success(f"[UI] 联系人: {'OK' if ok else '未找到'}")
    time.sleep(0.6)
except Exception as e:
    logger.warning(f"[UI] 搜索异常: {e}")

logger.info("[UI] 确认发送...")
try:
    nav.confirm_send()
    logger.success("[UI] 发送完成!")
except Exception as e:
    logger.warning(f"[UI] 发送异常: {e}")

logger.info("[*] 等 4s DB 写入...")
time.sleep(4)
_save()
