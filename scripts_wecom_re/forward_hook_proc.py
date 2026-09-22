"""
forward_hook_proc.py — 进程 1 (System Python311 + frida)
启动 INSERT hook，等 flag，捕获转发 INSERT，写结果 JSON
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
OUT.mkdir(parents=True, exist_ok=True)

BASELINE_BT0 = {
    0x9052c51, 0x3130178, 0x8ff5bd5, 0x90af838, 0x90b41d2,
    0x90958de, 0x90cc7ed, 0x901b087, 0x90a9f91, 0x90cc49a,
    0x90d17b2, 0x90febaf
}

def get_main_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
print(f"[Frida] PID={pid}", flush=True)

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
        send({{t:'insert', n:HIT, strs:strs, bt:bt, bt0:bt0, isNew:isNew, tid:this.threadId}});
    }}
}});
send({{t:'ready'}});
"""

events = []
new_events = []

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    t = p.get("t","")
    if t == "ready":
        print("[Frida] Hook READY - 写 flag", flush=True)
        (OUT / "forward_hook_ready.flag").write_text("ready")
    elif t == "insert":
        events.append(p)
        strs = p.get("strs", [])
        bt = p.get("bt", [])
        bt0 = p.get("bt0", 0)
        n = p.get("n", 0)
        is_new = p.get("isNew", False)
        sql = next((s for s in strs if s), "")
        mark = "NEW" if is_new else "   "
        print(f"[{mark}] INSERT #{n} bt0=0x{bt0:x} | {sql[:80]!r}", flush=True)
        if is_new:
            new_events.append(p)

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()

# 等 UI 进程的结束 flag (最多 120s)
print("[Frida] 等待 UI 进程完成转发...", flush=True)
DONE_FLAG = OUT / "forward_ui_done.flag"
DONE_FLAG.unlink(missing_ok=True)

start = time.time()
while time.time() - start < 120:
    if DONE_FLAG.exists():
        print("[Frida] UI 完成，再等 3s 捕获 DB 写入...", flush=True)
        time.sleep(3)
        break
    time.sleep(0.5)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"auto_forward_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")

print(f"\n[*] 总INSERT={len(events)}, NEW={len(new_events)}", flush=True)
if new_events:
    print("[🎯] 转发专属 INSERT 已捕获！", flush=True)
    for ev in new_events:
        strs = ev.get("strs", [])
        bt = ev.get("bt", [])
        sql = next((s for s in strs if s), "")
        print(f"  bt0=0x{ev['bt0']:x}", flush=True)
        print(f"  SQL={sql[:150]!r}", flush=True)
        print(f"  bt={bt[:4]}", flush=True)
else:
    print("[!] 无 NEW INSERT", flush=True)

print(f"[*] 结果 -> {out_f}", flush=True)
