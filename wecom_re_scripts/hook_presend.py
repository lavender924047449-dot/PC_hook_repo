# hook_presend.py — 直接 hook PreSendNewMessage (RVA 0x919ffb2)
# 目标：dump 参数里的 task / msg / conv 对象结构，找 proto/conv_id/msgtype

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 60
PRESEND_RVA = 0x919ffb2

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var hookPtr = mod.base.add(0x919ffb2);
var n = 0;
var MAX = 8;

function safeBytes(a, sz) {
    try {
        var p = ptr(a);
        if (p.toUInt32() < 0x10000 || p.toUInt32() > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab); var s = '';
    for (var i=0; i<a.length; i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function u32(a, i) { return ((a[i]|(a[i+1]<<8)|(a[i+2]<<16)|(a[i+3]<<24))>>>0); }
function asciiStr(ab) {
    var a = new Uint8Array(ab), out = [], run = '', st = 0;
    for (var i=0; i<a.length; i++) {
        if (a[i] >= 0x20 && a[i] <= 0x7E) {
            if (!run.length) st = i;
            run += String.fromCharCode(a[i]);
        } else {
            if (run.length >= 4) out.push({o:st, s:run});
            run = '';
        }
    }
    if (run.length >= 4) out.push({o:st, s:run});
    return out;
}

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (n >= MAX) return;
        n++;

        var argInfo = [];
        for (var ai=0; ai<4; ai++) {
            var av = args[ai].toUInt32();
            var entry = {i: ai, addr: '0x'+av.toString(16)};
            var raw = safeBytes(av, 512);
            if (raw) {
                entry.hex = toHex(raw);
                // 提取内部 ASCII
                entry.strs = asciiStr(raw).slice(0, 8);
                // 提取前 16 个 dword 作为 ptr 候选
                var arr = new Uint8Array(raw);
                var ptrs = [];
                for (var i=0; i+3 < Math.min(arr.length, 128); i += 4) {
                    var pv = u32(arr, i);
                    if (pv > 0x00400000 && pv < 0x7F000000) {
                        // 追一层看内容
                        var sub = safeBytes(pv, 128);
                        if (sub) {
                            var subStrs = asciiStr(sub).slice(0, 3).map(function(x){return x.s;});
                            ptrs.push({off:i, p:'0x'+pv.toString(16), sub_hex: toHex(sub).slice(0, 64), sub_strs: subStrs});
                        }
                    }
                }
                entry.ptrs = ptrs.slice(0, 12);
            }
            argInfo.push(entry);
        }

        // backtrace
        var bt = [];
        try { bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,5).map(function(a){return a.toString();}); } catch(e){}

        send({
            t:'hit', n:n,
            esp: this.context.esp.toString(),
            ebp: this.context.ebp.toString(),
            args: argInfo,
            bt: bt
        });
    }
});

send({t:'ready', hook: hookPtr.toString(), rva: '0x919ffb2', modBase: mod.base.toString()});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('无 :9882')

hits = []
def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']; t = p.get('t')
    if t == 'ready':
        print(f'[+] HOOK @ {p["hook"]}  RVA={p["rva"]}  base={p["modBase"]}', flush=True); return
    if t != 'hit': return

    # 立刻落盘
    hits.append(p)
    with (OUT_DIR/f'hook_presend_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    print(f'\n{"="*72}\n★ HIT #{p["n"]}  esp={p["esp"]}  ebp={p["ebp"]}', flush=True)
    print(f'  backtrace: {p["bt"][:3]}', flush=True)
    for a in p['args']:
        strs_preview = ', '.join([s['s'][:40] for s in a.get('strs', [])[:4]])
        print(f'  args[{a["i"]}] = {a["addr"]}  strs=[{strs_preview}]', flush=True)
        for pt in a.get('ptrs', [])[:6]:
            sub_p = ' | '.join(pt['sub_strs'][:2]) if pt['sub_strs'] else pt['sub_hex'][:32]
            print(f'      +0x{pt["off"]:02x}: {pt["p"]} → {sub_p}', flush=True)

print('[*] PID...', flush=True)
pid = get_pid()
print(f'    PID={pid}', flush=True)
print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()

import time
print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内在企微【发一条文字消息 + 一个小文件】', flush=True)
time.sleep(CAPTURE_SEC)
sc.unload(); sess.detach()

print(f'\n[+] 共 {len(hits)} 次 HIT', flush=True)
os._exit(0)
