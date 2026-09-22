"""
hook_forward_diff.py
差分监听：已知的背景 INSERT 调用者 → 只报告新出现的调用者 = 转发专属

背景调用者 (10分钟基线):
  0x9052c51  x15  KeyValues
  0x3130178  x6   9列 message
  0x8ff5bd5  x6   replace %1%
  0x90af838  x6   insert or ignore
  0x90b41d2  x6   5列 replace
  0x90958de  x4   replace
  0x90cc7ed  x4   AppInfo
  0x901b087  x2   AddKeyValues
  0x90a9f91  x2   replace(%s,%s)
  0x90cc49a  x2   AppInfo
  0x90d17b2  x2   msgid
  0x90febaf  x2   4列 replace
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
baseline_str = "[" + ",".join(f"0x{x:x}" for x in sorted(BASELINE_BT0)) + "]"

def get_main_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
print(f"[*] PID = {pid}")
dev = frida.get_local_device()

JS = f"""
'use strict';
var TARGET = ptr(0x1023810);
var BASELINE = {baseline_str};
var BASELINE_SET = {{}};
BASELINE.forEach(function(a){{ BASELINE_SET[a] = 1; }});
var HIT = 0;
var ALL_INSERT = 0;
var NEW_INSERT = [];

function ss(p) {{
    try {{
        if(!p || p.isNull()) return '';
        var s = p.readCString(250);
        return s ? s.slice(0, 200) : '';
    }} catch(e) {{ return ''; }}
}}

Interceptor.attach(TARGET, {{
    onEnter: function(args) {{
        HIT++;
        if (HIT > 50000) return;
        
        var strs = [];
        for (var i = 0; i < 6; i++) strs.push(ss(args[i]));
        
        var isInsert = strs.some(function(s){{
            return s.match(/^(INSERT|REPLACE)/i);
        }});
        if (!isInsert) return;
        
        ALL_INSERT++;
        var bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 8)
                       .map(function(a){{return a.toString();}});
        
        var bt0 = bt.length > 0 ? parseInt(bt[0], 16) : 0;
        var isBaseline = !!BASELINE_SET[bt0];
        
        send({{
            t: 'insert',
            n: HIT,
            strs: strs,
            bt: bt,
            bt0: bt0,
            isNew: !isBaseline,
            tid: this.threadId
        }});
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
        print("\n" + "="*65)
        print("[READY] 差分监听已启动 - 只报告转发专属的 INSERT!")
        print(">>> 请立刻: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        print("="*65)
        OUT.joinpath("diff_hook_ready.flag").write_text("ready")
    elif t == "insert":
        events.append(p)
        is_new = p.get("isNew", False)
        strs = p.get("strs", [])
        bt = p.get("bt", [])
        bt0 = p.get("bt0", 0)
        n = p.get("n", 0)
        
        if is_new:
            new_events.append(p)
            sql = next((s for s in strs if s), "")
            print(f"\n🆕 [NEW INSERT #{n}] bt[0]=0x{bt0:x}")
            print(f"  sql: {sql[:100]!r}")
            for i, s in enumerate(strs[1:4], 1):
                if s: print(f"  arg[{i}]: {s[:60]!r}")
            print(f"  bt: {bt[:4]}")

sess = dev.attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()

DURATION = 300  # 5分钟
print(f"[*] 监听 {DURATION}s (5分钟)...")
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    pass

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"forward_diff_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
all_inserts = [e for e in events if e.get("t") == "insert"]
print(f"\n[*] 完成: 总INSERT={len(all_inserts)}, 新(非背景)={len(new_events)} -> {out_f}")
