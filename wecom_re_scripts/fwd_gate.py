# fwd_gate.py -- 转发 CGI 门控捕获（短窗口版，防卡死）
# ===========================================================
# 在 RVA 0x390B39 (CGI 热路径) 设门控 a1='01 28...'
# 捕获到转发后立即解除 hook，保存数据。
# 若 30s 内无转发，自动退出。
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/fwd_gate.py
# 然后立刻在企微执行消息转发！

import frida, subprocess, time, json, sys, threading, os, signal
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
RVA_CGI = 0x390B39
WINDOW_SEC = 60  # 1 分钟窗口

def get_pid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f"[+] PID = {pid}", flush=True)

JS = r"""
'use strict';
var wxBase = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxBase = mods[i].base; break;
    }
}
var HOOK = wxBase.add(0x390B39);
var hitCount = 0, fwdCount = 0;

function toHex(buf, n) {
    var a = new Uint8Array(buf, 0, Math.min(buf.byteLength, n || buf.byteLength));
    return Array.from(a).map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ');
}

Interceptor.attach(HOOK, {
    onEnter: function(args) {
        hitCount++;
        // 门控：args[1] 解引用前2字节 == 01 28
        var match = false;
        try {
            var b0 = args[1].readU8();
            var b1 = args[1].add(1).readU8();
            if (b0 === 0x01 && b1 === 0x28) match = true;
        } catch(e) { return; }
        if (!match) return;

        fwdCount++;
        if (fwdCount > 20) return;

        // 捕获完整数据
        var a0_hex='', a1_hex='', a2_deref='', a2_ptr='';
        try { a0_hex = toHex(args[0].readByteArray(32)); } catch(e){}
        try { a1_hex = toHex(args[1].readByteArray(32)); } catch(e){}

        var a2_int = 0;
        try { a2_int = args[2].toInt32(); } catch(e){}
        try { a2_ptr = toHex(args[2].readByteArray(32)); } catch(e){}
        try {
            var p = ptr(a2_int);
            if (!p.isNull()) a2_deref = toHex(p.readByteArray(256));
        } catch(e){}

        var bt = [];
        try {
            bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                       .slice(0, 8).map(function(a){ return a.toString(); });
        } catch(e){}

        send({
            t:'fwd', n:fwdCount, tot:hitCount, ts:Date.now(),
            tid: this.threadId,
            a0: a0_hex, a1: a1_hex,
            a2_int: a2_int, a2_hex: '0x'+(a2_int>>>0).toString(16),
            a2_ptr: a2_ptr, a2_deref: a2_deref,
            a3: (function(){ try{return args[3].toInt32();}catch(e){return 0;} })(),
            bt: bt
        });
    }
});

send({t:'ready', base:wxBase.toString(), addr:HOOK.toString()});
"""

captures = []
done = threading.Event()

def on_message(msg, data):
    if msg.get("type") == "error":
        print(f"[Frida ERR] {msg.get('description','')}", flush=True)
        return
    if msg.get("type") != "send": return
    p = msg["payload"]
    t = p.get("t","")
    if t == "ready":
        print(f"[+] Hook READY @ {p.get('addr')}  base={p.get('base')}", flush=True)
        print(f"\n{'*'*60}", flush=True)
        print(f"*** 请立刻在企微执行消息转发！({WINDOW_SEC}s 内) ***", flush=True)
        print(f"{'*'*60}\n", flush=True)
    elif t == "fwd":
        captures.append(p)
        ts_s = datetime.fromtimestamp(p["ts"]/1000).strftime("%H:%M:%S")
        print(f"\n[★ FORWARD HIT #{p['n']}]  {ts_s}  tid={p['tid']}", flush=True)
        print(f"  a0 = {p.get('a0','')[:64]}", flush=True)
        print(f"  a1 = {p.get('a1','')[:64]}", flush=True)
        print(f"  a2_hex = {p.get('a2_hex')}", flush=True)
        if p.get("a2_deref"):
            dref = p["a2_deref"]
            # 尝试 ASCII 解码
            try:
                raw = bytes(int(x, 16) for x in dref.split())
                txt = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
                print(f"  a2_deref_ascii = {txt[:100]!r}", flush=True)
                print(f"  a2_deref[0:64] = {dref[:64]}", flush=True)
            except: pass
        if len(captures) >= 5:
            print(f"\n[+] 已捕获 5 条，停止 hook", flush=True)
            done.set()

print(f"[*] Attaching...", flush=True)
try:
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(JS)
    sc.on("message", on_message)
    sc.load()
except Exception as e:
    print(f"[ERR] Attach 失败: {e}", flush=True)
    sys.exit(1)

# 等待完成（最多 WINDOW_SEC 秒）
done.wait(timeout=WINDOW_SEC)

# 强制保存并退出（不等 unload，避免卡死）
ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
out_path = OUT_DIR / f"fwd_gate_{ts_str}.json"
out_path.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding="utf-8")

if captures:
    print(f"\n[+] 捕获 {len(captures)} 条 -> {out_path}", flush=True)
    print(f"\n[=== 摘要 ===]", flush=True)
    for c in captures[:3]:
        print(f"  a1 = {c.get('a1','')}  a2_hex = {c.get('a2_hex')}", flush=True)
        if c.get("a2_deref"):
            raw = bytes(int(x,16) for x in c["a2_deref"].split())
            txt = "".join(chr(b) if 32<=b<127 else "." for b in raw)
            print(f"  a2_ascii = {txt[:80]!r}", flush=True)
else:
    print(f"\n[!] 未捕获 -> {out_path}", flush=True)
    print(f"    可能原因：1) 未执行转发  2) hook 地址 args 结构有变化", flush=True)

# 强制退出（不调用 unload/detach，避免高频 hook 卡死）
print(f"[+] 完成，强制退出", flush=True)
os._exit(0)
