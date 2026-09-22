"""
hook_insert_wait.py
Hook 0x1023810 (SQL builder) — 更长的时间窗口 + 更完整的 args 捕获
捕获 INSERT/REPLACE 操作，用于转发逆向
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

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

JS = r"""
'use strict';
var TARGET = ptr(0x1023810);
var HIT = 0;

function safeStr(p) {
    try {
        if (!p || p.isNull()) return '';
        var s = p.readCString(300);
        return s ? s.slice(0, 200) : '';
    } catch(e) { return ''; }
}

Interceptor.attach(TARGET, {
    onEnter: function(args) {
        HIT++;
        if (HIT > 10000) return;
        
        // 读 0-7 号 arg 的字符串
        var strs = [];
        for (var i = 0; i < 8; i++) {
            strs.push(safeStr(args[i]));
        }
        
        // 也读 ESP 上方的内存（stack dump）
        var espVal = [];
        try {
            var esp = this.context.esp;
            var raw = new Uint8Array(esp.readByteArray(32));
            for (var j = 0; j < raw.length; j++) espVal.push(raw[j]);
        } catch(e) {}
        
        // ECX (this pointer)
        var ecx = this.context.ecx.toString();
        
        // 判断是否有 SQL
        var hasSql = strs.some(function(s) {
            return s.match(/^(SELECT|INSERT|REPLACE|UPDATE|DELETE|PRAGMA|BEGIN|COMMIT|select|insert|replace|update)/);
        });
        if (!hasSql && HIT > 10) return;
        
        // 判断是否是 INSERT/REPLACE
        var isInsert = strs.some(function(s){
            return s.match(/^(INSERT|REPLACE|replace|insert)/i);
        });
        
        var bt = [];
        if (isInsert) {
            bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,8)
                       .map(function(a){return a.toString();});
        }
        
        send({
            t: 'q',
            n: HIT,
            strs: strs,
            ecx: ecx,
            esp: espVal,
            isInsert: isInsert,
            tid: this.threadId,
            bt: bt
        });
    }
});
send({t:'ready'});
"""

events = []
all_inserts = []

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    t = p.get("t","")
    if t == "ready":
        print("\n" + "="*60)
        print("[READY] SQL builder hook active!")
        print(">>> 请【立刻】执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        print("="*60)
        OUT.joinpath("insert_wait_ready.flag").write_text("ready")
        return
    
    events.append(p)
    is_insert = p.get("isInsert", False)
    strs = p.get("strs", [])
    n = p.get("n", 0)
    
    if is_insert:
        all_inserts.append(p)
        # 打印第一个有内容的字符串
        sql_str = next((s for s in strs if s), "")
        bt = p.get("bt", [])
        print(f"\n[INSERT #{n}] strs[0]={strs[0][:80]!r}")
        if len(strs) > 1:
            for i, s in enumerate(strs[1:4], 1):
                if s:
                    print(f"  arg[{i}]={s[:60]!r}")
        if bt:
            print(f"  bt: {' | '.join(bt[:3])}")

sess = dev.attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()

DURATION = 180  # 3分钟窗口
print(f"[*] 监听 {DURATION}s (3分钟)，请在 [READY] 后立刻执行转发...")

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    pass

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"insert_wait_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 完成: INSERT={len(all_inserts)} 条, 总事件={len(events)} -> {out_f}")
