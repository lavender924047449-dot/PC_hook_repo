"""
hook_call_1023810.py
Hook 0x1023810 (INSERT OR REPLACE 模板 PUSH 后立即 CALL 的函数)
验证：
1. 它是否是 sqlite3_prepare_v2 包装器
2. 是否在转发时被调用
3. args 中是否有 SQL 字符串

同时 hook 全局任何 DB 操作（5s 内应有活动），确认地址有效性
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
OUT.mkdir(parents=True, exist_ok=True)

def get_main_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
print(f"[*] PID = {pid}")
dev = frida.get_local_device()

# Hook 0x1023810 - 读前 3 字节验证是否是函数 prologue
JS = """
'use strict';

var TARGET = ptr(0x1023810);

// 先读字节验证
var verifyBytes = [];
try {
    var raw = new Uint8Array(TARGET.readByteArray(6));
    for (var i=0; i<6; i++) verifyBytes.push(raw[i]);
} catch(e) {}
send({t:'verify', addr:TARGET.toString(), bytes:verifyBytes});

var HIT = 0;
var SQL_HITS = 0;
Interceptor.attach(TARGET, {
    onEnter: function(args) {
        if (HIT++ > 2000) return;
        
        // 尝试从 args 中读字符串
        var sql = '', db = '';
        for (var ai = 0; ai < 4; ai++) {
            try {
                var s = args[ai].readCString(300);
                if (s && s.length > 5) {
                    if (s.indexOf('.db') >= 0) db = s;
                    else if (s.match(/^(SELECT|INSERT|UPDATE|DELETE|CREATE|REPLACE|BEGIN|COMMIT)/i)) sql = s;
                }
            } catch(e) {}
        }
        
        if (HIT <= 5 || sql) {
            var bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,4)
                          .map(function(a){return a.toString();});
            send({t:'hit', n:HIT, sql:sql, db:db, tid:this.threadId, bt:bt});
            if (sql) SQL_HITS++;
        }
    }
});
send({t:'hook_ready', addr:TARGET.toString()});
"""

events = []
hook_ok = False

def on_msg(msg, data):
    global hook_ok
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    events.append(p)
    t = p.get("t","")
    if t == "verify":
        b = p["bytes"]
        hexb = " ".join(f"{x:02x}" for x in b)
        is_prolog = len(b) >= 2 and (b[0] == 0x55 or b[0] in range(0x50,0x58) or b[0] == 0x56)
        print(f"[verify] bytes={hexb}  prolog={is_prolog}")
    elif t == "hook_ready":
        hook_ok = True
        print(f"[HOOK READY] {p['addr']}")
        print(">>> 现在执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        OUT.joinpath("call_hook_ready.flag").write_text("ready")
    elif t == "hit":
        sql = p.get("sql","")
        n = p.get("n", 0)
        db = p.get("db","")
        if sql:
            print(f"\n[SQL HIT #{n}] sql={sql[:120]!r}")
            print(f"  db={db!r}  tid={p.get('tid','')}")
            print(f"  bt={p.get('bt',[][:2])}")
        elif n <= 5:
            print(f"  [hit #{n}] no sql, tid={p.get('tid','')}")

sess = dev.attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
print("[*] 等待 hook 加载...")
time.sleep(3)

if not hook_ok:
    print("[!] hook_ready 未收到，继续等待...")

print("[*] 监听 90s (先静默观察 5s，有背景活动说明地址正确)...")
try:
    time.sleep(90)
except KeyboardInterrupt:
    pass

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
hits = [e for e in events if e.get("t") == "hit"]
sql_hits = [h for h in hits if h.get("sql")]
out_f = OUT / f"call_hook_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 完成: {len(hits)} 次命中, {len(sql_hits)} 条 SQL -> {out_f}")
