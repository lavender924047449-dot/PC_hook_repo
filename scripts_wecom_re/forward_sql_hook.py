"""
forward_sql_hook.py
用旧 session 的 RVA 定位 sqlite3_prepare_v2，hook 它捕获转发时的 SQL

上次 hook 地址: 0xa6316d0 (old base 0xDC0000)
RVA: 0x0A6316D0 - 0x00DC0000 = 0x0A5556D0
本次: 获取新基址 -> 新地址 = 新基址 + RVA

安全性: 只设置 1 个 hook，附加主进程一次，不做模块枚举
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
OUT.mkdir(parents=True, exist_ok=True)

SQLITE_RVA = 0x0A5556D0  # sqlite3_prepare_v2 的 RVA (从旧 session 计算)

def get_main_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
print(f"[*] PID = {pid}")

dev = frida.get_local_device()

JS_GET_BASE = """
var m = Process.getModuleByName('WXWork.exe');
send({base: m.base.toString(), size: m.size});
"""

# Phase 1: 获取模块基址
base_addr = None
def on_base(msg, data):
    global base_addr
    if msg.get("type") == "send":
        base_addr = int(msg["payload"]["base"], 16)
        print(f"  [base] WXWork.exe @ 0x{base_addr:08X}")

sess = dev.attach(pid)
sc0 = sess.create_script(JS_GET_BASE)
sc0.on("message", on_base)
sc0.load()
time.sleep(2)
sc0.unload()

if base_addr is None:
    print("ERROR: 无法获取模块基址")
    sys.exit(1)

hook_addr = base_addr + SQLITE_RVA
print(f"[*] Hook 目标: 0x{hook_addr:08X} (base=0x{base_addr:08X} + RVA=0x{SQLITE_RVA:08X})")

# Phase 2: 设置 1 个 hook
JS_HOOK = f"""
'use strict';
var TARGET = ptr(0x{hook_addr:X});
var HIT = 0;
var MAX = 200;

// 验证目标地址是否合理 (读前3字节)
try {{
    var bytes = new Uint8Array(TARGET.readByteArray(3));
    send({{t:'verify', bytes:[bytes[0],bytes[1],bytes[2]],
          addr:TARGET.toString()}});
}} catch(e) {{
    send({{t:'verify_err', e:e.message}});
}}

Interceptor.attach(TARGET, {{
    onEnter: function(args) {{
        if (HIT++ > MAX) return;
        // args[0] = sqlite3 db handle (contains file path at offset)
        // args[1] = sql string (UTF-8)
        // args[2] = nByte (-1 for auto)
        var sql = '';
        var dbpath = '';
        try {{
            sql = args[1].readCString(1024) || '';
        }} catch(e) {{}}
        try {{
            // db handle: first field is a pointer to pager, pager+offset has filename
            var dbh = args[0];
            if (!dbh.isNull()) {{
                // 尝试读 db 结构的文件名（固定偏移）
                for (var off = 0; off <= 256; off += 4) {{
                    try {{
                        var p = dbh.add(off).readPointer();
                        if (!p.isNull()) {{
                            var s = p.readCString(256);
                            if (s && s.indexOf('.db') >= 0 && s.indexOf('WXWork') >= 0) {{
                                dbpath = s;
                                break;
                            }}
                        }}
                    }} catch(e) {{}}
                }}
            }}
        }} catch(e) {{}}

        if (!sql) return;  // 跳过空 SQL

        var bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 6)
                       .map(function(a){{ return a.toString(); }});
        send({{t:'sql', sql:sql, db:dbpath, tid:this.threadId, bt:bt}});
    }}
}});
send({{t:'hook_ready', addr:TARGET.toString()}});
"""

events = []
sql_events = []

def on_hook(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    events.append(p)
    t = p.get("t", "")
    if t == "verify":
        b = p["bytes"]
        is_prologue = (b[0]==0x55 and b[1] in (0x8B,0x89)) or b[0] in (0x56,0x57,0x53)
        print(f"  [verify] addr={p['addr']} bytes={b}  prologue={is_prologue}")
    elif t == "verify_err":
        print(f"  [verify_err] {p.get('e','')}")
    elif t == "hook_ready":
        print(f"\n[HOOK READY] SQLite prepare @ {p['addr']}")
        print(">>> 请立刻执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        OUT.joinpath("forward_hook_ready.flag").write_text("ready")
    elif t == "sql":
        sql_events.append(p)
        sql = p.get("sql","")
        db = p.get("db","")
        tid = p.get("tid","")
        bt = p.get("bt",[])
        db_short = db.split("\\")[-1] if db else "?"
        # 只打印 INSERT / UPDATE / 包含 message 的 SQL
        if any(kw in sql.lower() for kw in ("insert", "update", "forward", "message", "send")):
            print(f"\n[SQL] db={db_short} tid={tid}")
            print(f"  SQL: {sql[:200]}")
            print(f"  bt:  {' | '.join(bt[:3])}")

sc1 = sess.create_script(JS_HOOK)
sc1.on("message", on_hook)
sc1.load()
print("[*] Hook 加载完成，监听 90s...")

DURATION = 90
try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] Ctrl+C")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"forward_sql_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 完成: {len(sql_events)} 条 INSERT/UPDATE/message SQL -> {out_f}")
