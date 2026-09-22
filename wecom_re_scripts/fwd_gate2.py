# fwd_gate2.py -- 转发 CGI 门控捕获 v2（先验证 hook 有效，再等转发）
# ===========================================================
# 改进：每 5 秒打印一次 hitCount（验证 hook 确实在触发）
# 窗口延长到 120s，捕获后立刻保存 + os._exit

import frida, subprocess, time, json, sys, threading, os
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
RVA_CGI = 0x390B39
WINDOW_SEC = 120

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
        // 快速门控：a1[0]==01, a1[1]==28
        try {
            if (args[1].readU8() !== 0x01) return;
            if (args[1].add(1).readU8() !== 0x28) return;
        } catch(e) { return; }

        fwdCount++;
        if (fwdCount > 20) return;

        var a0='', a1='', a2p='', a2d='';
        try { a0 = toHex(args[0].readByteArray(32)); } catch(e){}
        try { a1 = toHex(args[1].readByteArray(32)); } catch(e){}
        try { a2p = toHex(args[2].readByteArray(32)); } catch(e){}
        var a2i = 0;
        try { a2i = args[2].toInt32(); } catch(e){}
        try {
            var p = ptr(a2i);
            if (!p.isNull()) a2d = toHex(p.readByteArray(256));
        } catch(e){}

        var bt=[];
        try { bt = Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,8).map(function(a){return a.toString();}); }catch(e){}

        send({t:'fwd',n:fwdCount,tot:hitCount,ts:Date.now(),tid:this.threadId,
              a0:a0,a1:a1,a2_int:a2i,a2_hex:'0x'+(a2i>>>0).toString(16),
              a2_ptr:a2p,a2_deref:a2d,bt:bt});
    }
});

// 每5秒报告一次 hitCount
setInterval(function() {
    send({t:'tick', hit:hitCount, fwd:fwdCount, ts:Date.now()});
}, 5000);

send({t:'ready', base:wxBase.toString(), addr:HOOK.toString()});
"""

captures = []
done = threading.Event()
last_tick = [0]

def on_message(msg, data):
    if msg.get("type") == "error":
        print(f"[Frida ERR] {msg.get('description','')}", flush=True)
        return
    if msg.get("type") != "send": return
    p = msg["payload"]
    t = p.get("t","")
    if t == "ready":
        print(f"[+] Hook READY @ {p.get('addr')}  base={p.get('base')}", flush=True)
        print(f"\n{'='*60}", flush=True)
        print(f"★ 请在企微中执行消息转发！（120s 内）★", flush=True)
        print(f"  操作：右键聊天消息 → 转发 → 选择联系人 → 发送", flush=True)
        print(f"  或：长按消息 → 更多 → 转发", flush=True)
        print(f"{'='*60}", flush=True)
        print(f"(每5秒显示一次 hook 计数，确认 hook 正常工作...)", flush=True)
    elif t == "tick":
        hit = p.get("hit", 0)
        fwd = p.get("fwd", 0)
        now_s = datetime.fromtimestamp(p["ts"]/1000).strftime("%H:%M:%S")
        print(f"  [{now_s}] hits={hit}  fwd_matches={fwd}", flush=True)
        last_tick[0] = hit
    elif t == "fwd":
        captures.append(p)
        ts_s = datetime.fromtimestamp(p["ts"]/1000).strftime("%H:%M:%S")
        print(f"\n[★ FORWARD CAPTURED #{p['n']}]  {ts_s}", flush=True)
        print(f"  a1 = {p.get('a1','')[:48]}", flush=True)
        print(f"  a2_hex = {p.get('a2_hex')}  a2_ptr = {p.get('a2_ptr','')[:32]}", flush=True)
        if p.get("a2_deref"):
            try:
                raw = bytes(int(x,16) for x in p["a2_deref"].split())
                txt = "".join(chr(b) if 32<=b<127 else "." for b in raw)
                print(f"  a2_ascii = {txt[:100]!r}", flush=True)
            except: pass
        if len(captures) >= 5:
            print(f"[+] 已捕获5条，触发退出", flush=True)
            done.set()

print(f"[*] Attaching...", flush=True)
try:
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(JS)
    sc.on("message", on_message)
    sc.load()
except Exception as e:
    print(f"[ERR] {e}", flush=True)
    sys.exit(1)

done.wait(timeout=WINDOW_SEC)

ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
out_path = OUT_DIR / f"fwd_gate2_{ts_str}.json"
out_path.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding="utf-8")

print(f"\n{'='*60}", flush=True)
if captures:
    print(f"[OK] 捕获 {len(captures)} 条转发 CGI -> {out_path}", flush=True)
    for c in captures[:3]:
        print(f"  a1={c.get('a1','')} a2_hex={c.get('a2_hex')}", flush=True)
        if c.get("a2_deref"):
            raw = bytes(int(x,16) for x in c["a2_deref"].split())
            print(f"  a2_ascii={repr(''.join(chr(b) if 32<=b<127 else '.' for b in raw)[:100])}", flush=True)
else:
    hit = last_tick[0]
    print(f"[FAIL] 未捕获转发 (最后 hitCount={hit})", flush=True)
    if hit == 0:
        print(f"  [!] hitCount=0 说明 hook 未触发 -- 地址可能无效", flush=True)
    else:
        print(f"  [!] hook 有效（hitCount={hit}次），但未见 a1=01 28 -- 转发未执行", flush=True)

os._exit(0)
