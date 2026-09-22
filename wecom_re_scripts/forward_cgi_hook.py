# forward_cgi_hook.py -- 转发 CGI 精确门控 hook
# ============================================================
# 目标：在 CGI 热路径 (RVA 0x390B39) 上设置精确门控，
#       只在 a1 模式匹配 '01 28...'（已确认的转发指纹）时，
#       捕获完整参数和 a2 指针内容（可能是 Protobuf 明文）。
#
# 已知转发模式（来自 cgi_diff_20260910_213903.json）：
#   a1 = 01 28 23 29 23 2a 23 2b ...
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/forward_cgi_hook.py
# 然后在企微执行消息转发，脚本自动捕获并保存。

import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

RVA_CGI_HOTPATH = 0x390B39   # CGI 热路径内某指令位置（33次/秒）
TIMEOUT_SEC = 180             # 3 分钟观察窗口

def get_main_pid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("未找到 :9882 LISTENING -- 请先启动企微")

pid = get_main_pid()
print(f"[+] PID = {pid}", flush=True)

JS = r"""
'use strict';

// 动态找 WXWork.exe 基址
var mods = Process.enumerateModules();
var wxBase = null;
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxBase = mods[i].base;
        break;
    }
}
if (!wxBase) {
    send({t:'err', msg:'WXWork.exe not found'});
    throw new Error('abort');
}

var RVA = 0x390B39;
var HOOK_ADDR = wxBase.add(RVA);

send({t:'init', base: wxBase.toString(), addr: HOOK_ADDR.toString()});

var hitTotal = 0;
var fwdHits = 0;

function toHex(arr) {
    return Array.from(arr).map(function(b){
        return ('0'+b.toString(16)).slice(-2);
    }).join(' ');
}

function safeReadBytes(ptr, n) {
    try {
        if (!ptr || ptr.isNull()) return null;
        return new Uint8Array(ptr.readByteArray(n));
    } catch(e) { return null; }
}

function safeDerefRead(val, n) {
    // val 是整数地址，尝试作为指针读取
    try {
        var p = ptr(val);
        if (p.isNull()) return null;
        return new Uint8Array(p.readByteArray(n));
    } catch(e) { return null; }
}

Interceptor.attach(HOOK_ADDR, {
    onEnter: function(args) {
        hitTotal++;

        // 快速读 args[1] 前 2 字节作门控
        var a1_b = safeReadBytes(args[1], 2);
        if (!a1_b) return;
        if (a1_b[0] !== 0x01 || a1_b[1] !== 0x28) return;

        // === 命中转发模式 ===
        fwdHits++;
        if (fwdHits > 30) return;  // 安全上限

        var a0_b = safeReadBytes(args[0], 32);
        var a1_b32 = safeReadBytes(args[1], 32);
        var a2_int = args[2].toInt32();

        // 尝试将 a2 当作指针读取 256 字节
        var a2_deref = safeDerefRead(a2_int, 256);

        // 也尝试读 args[2] 作为字节数组（可能是 Protobuf 结构体指针）
        var a2_as_ptr = safeReadBytes(args[2], 32);

        // 尝试读更多 args
        var a3_int = 0, a4_int = 0;
        try { a3_int = args[3].toInt32(); } catch(e) {}
        try { a4_int = args[4].toInt32(); } catch(e) {}

        // 简单 FUZZY backtrace（最多 12 帧，安全）
        var bt = [];
        try {
            bt = Thread.backtrace(this.context, Backtracer.FUZZY)
                       .slice(0, 12)
                       .map(function(a){ return a.toString(); });
        } catch(e) {}

        send({
            t:       'fwd',
            n:       fwdHits,
            tot:     hitTotal,
            ts:      Date.now(),
            tid:     this.threadId,
            a0:      a0_b ? toHex(a0_b) : null,
            a1:      a1_b32 ? toHex(a1_b32) : null,
            a2_int:  a2_int,
            a2_hex:  '0x' + (a2_int >>> 0).toString(16),
            a2_deref: a2_deref ? toHex(a2_deref) : null,
            a2_ptr:  a2_as_ptr ? toHex(a2_as_ptr) : null,
            a3_int:  a3_int,
            a4_int:  a4_int,
            bt:      bt,
        });
    }
});

send({t:'ready', addr: HOOK_ADDR.toString(), rva: '0x390B39'});
"""

captures = []

def on_message(msg, data):
    if msg.get("type") != "send":
        if msg.get("type") == "error":
            print(f"[Frida ERROR] {msg.get('description','')}", flush=True)
        return
    p = msg["payload"]
    t = p.get("t","")
    if t == "init":
        print(f"[+] WXWork.exe base = {p['base']}", flush=True)
        print(f"[+] Hook addr = {p['addr']}", flush=True)
    elif t == "ready":
        print(f"[+] Hook READY @ {p['addr']}  (RVA {p['rva']})", flush=True)
        print(f"\n>>> 请在企微执行消息转发！（等待转发 CGI 触发，最多 3 分钟）<<<\n", flush=True)
    elif t == "err":
        print(f"[ERR] {p['msg']}", flush=True)
    elif t == "fwd":
        captures.append(p)
        ts_s = datetime.fromtimestamp(p["ts"]/1000).strftime("%H:%M:%S")
        print(f"\n{'★'*60}", flush=True)
        print(f"[FORWARD HIT #{p['n']}]  ts={ts_s}  tid={p['tid']}", flush=True)
        print(f"  a0 = {p.get('a0','')[:64]}", flush=True)
        print(f"  a1 = {p.get('a1','')[:64]}", flush=True)
        print(f"  a2_hex = {p.get('a2_hex')}  (int={p.get('a2_int')})", flush=True)
        if p.get("a2_deref"):
            dref = p["a2_deref"]
            print(f"  a2_deref[0:64]  = {dref[:64]}", flush=True)
            print(f"  a2_deref[64:128]= {dref[63:127]}", flush=True)
            # 尝试打印可读字符
            try:
                raw = bytes(int(x, 16) for x in dref.split())
                txt = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
                print(f"  a2_deref ASCII = {txt[:80]!r}", flush=True)
            except: pass
        if p.get("a2_ptr"):
            print(f"  a2 as ptr[0:32] = {p['a2_ptr'][:48]}", flush=True)
        print(f"  a3={p.get('a3_int')}  a4={p.get('a4_int')}", flush=True)
        print(f"  backtrace:", flush=True)
        for f in p.get("bt", []):
            print(f"    {f}", flush=True)

print(f"[*] Attaching to PID {pid}...", flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_message)
sc.load()
time.sleep(2)

# 等待转发触发（3 分钟窗口）
time.sleep(TIMEOUT_SEC)

sc.unload()
sess.detach()
print(f"\n[+] Hook unloaded & session detached", flush=True)

# 保存结果
ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
out_path = OUT_DIR / f"forward_cgi_{ts_str}.json"
out_path.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"[+] 保存 {len(captures)} 条转发 CGI 事件 -> {out_path}", flush=True)

if captures:
    print(f"\n[=== 分析摘要 ===]", flush=True)
    for c in captures[:3]:
        print(f"  a1 = {c.get('a1','')}", flush=True)
        print(f"  a2_hex = {c.get('a2_hex')}", flush=True)
        if c.get("a2_deref"):
            raw = bytes(int(x, 16) for x in c["a2_deref"].split())
            txt = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            print(f"  a2_deref_ascii = {txt[:100]!r}", flush=True)
else:
    print(f"[!] 未捕获到转发 CGI — 可能转发未在窗口内执行，或 hook 地址需调整", flush=True)
