# hook_voice_xrefs.py — hook voice 字符串的 4 处 .text xref 附近的函数
# 目标：看这些函数是不是 msgtype 判断 / voice 构造相关

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')

# voice 的 4 处 xref（Frida 之前给出的地址，需要减 base 得 RVA）
# xref address 是 mov reg, imm32 的 imm32 位置，回退找 prologue
XREF_ADDRS_RVA = [
    0xfa5bd6 - 0x5e0000,   # 0x9c5bd6
    0x3537b3b - 0x5e0000,  # 0x2f57b3b
    0x3537bfb - 0x5e0000,  # 0x2f57bfb
    # 第 4 个 xref 我们不知道（只 dump 了 first 3）
]

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var xrefsRva = %XREFS%;

// 严格 prologue: 前 1B 是 CC / C3
function findProStrict(addr, maxBack) {
    for (var i=4; i<(maxBack||0x600); i++) {
        try {
            var p = addr.sub(i);
            var b0 = p.readU8(), b1 = p.add(1).readU8(), b2 = p.add(2).readU8();
            if (!(b0 === 0x55 && b1 === 0x8b && b2 === 0xec)) continue;
            var prev = p.sub(1).readU8();
            if (prev === 0xcc || prev === 0xc3) return {addr: p, dist: i};
            if (i >= 3 && p.sub(3).readU8() === 0xc2) return {addr: p, dist: i};
        } catch(e){ break; }
    }
    return null;
}

function safeBytes(a, sz) {
    try { var p = ptr(a); var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e){ return null; }
}
function toHex(ab) { var a=new Uint8Array(ab), s=''; for (var i=0;i<a.length;i++) s+=('0'+a[i].toString(16)).slice(-2); return s; }
function asciiStrs(ab, min) {
    var a=new Uint8Array(ab), out=[], run='', st=0;
    for (var i=0;i<a.length;i++) {
        if (a[i]>=0x20 && a[i]<=0x7E) { if(!run) st=i; run+=String.fromCharCode(a[i]); }
        else { if (run.length>=(min||4)) out.push({o:st, s:run}); run=''; }
    }
    if (run.length>=(min||4)) out.push({o:st, s:run});
    return out;
}

// 对每个 xref 找 prologue 并 hook
for (var xi=0; xi<xrefsRva.length; xi++) {
    var xrefAbs = mod.base.add(xrefsRva[xi]);
    var pro = findProStrict(xrefAbs, 0x600);
    if (!pro) {
        send({t:'setup', xi:xi, xref_rva:'0x'+xrefsRva[xi].toString(16), status:'no_prologue'});
        continue;
    }
    var funcRva = '0x'+pro.addr.sub(mod.base).toString(16);
    send({t:'setup', xi:xi, xref_rva:'0x'+xrefsRva[xi].toString(16),
          func:pro.addr.toString(), func_rva:funcRva, dist:pro.dist});

    (function(idx, fnPtr, fnRva) {
        var hitCount = 0;
        Interceptor.attach(fnPtr, {
            onEnter: function(args) {
                hitCount++;
                if (hitCount > 3) return;
                var info = { xi: idx, fn: fnRva, hit: hitCount, args: [] };
                for (var ai=0; ai<4; ai++) {
                    var av = args[ai].toUInt32();
                    var ent = { i: ai, addr: '0x'+av.toString(16) };
                    var raw = safeBytes(av, 256);
                    if (raw) {
                        ent.strs = asciiStrs(raw, 4).slice(0, 6);
                        ent.hex = toHex(raw).slice(0, 128);
                    }
                    info.args.push(ent);
                }
                send({t:'hit', data: info});
            }
        });
    })(xi, pro.addr, funcRva);
}

send({t:'ready'});
"""
JS = JS.replace('%XREFS%', json.dumps(XREF_ADDRS_RVA))

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

hits = []
def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:300]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']; t = p.get('t')
    if t == 'ready':
        print(f'[+] All hooks armed', flush=True); return
    if t == 'setup':
        if p.get('status') == 'no_prologue':
            print(f'  [xi={p["xi"]}] xref {p["xref_rva"]}: NO PROLOGUE', flush=True)
        else:
            print(f'  [xi={p["xi"]}] xref {p["xref_rva"]} → func ★{p["func_rva"]} (back {p["dist"]}B)', flush=True)
        return
    if t == 'hit':
        d = p['data']; hits.append(d)
        print(f'\n★ HIT xi={d["xi"]} fn={d["fn"]} hit#{d["hit"]}', flush=True)
        for a in d['args']:
            strs = ', '.join([s['s'][:30] for s in a.get('strs', [])[:3]])
            print(f'  args[{a["i"]}]={a["addr"]}  strs=[{strs}]  hex={a.get("hex","")[:80]}', flush=True)

pid = get_pid(); print(f'[*] PID={pid}', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS); sc.on('message', on_msg); sc.load()

import time
print(f'\n{"="*72}\n★★★ 请在 60s 内：\n  1. 向 FTA 发一条文字\n  2. 手机往 FTA 发一条语音（让 PC 同步接收）\n  3. 向 FTA 发一个文件', flush=True)
time.sleep(60)
sc.unload(); sess.detach()
print(f'\n[+] 共 {len(hits)} 次 HIT', flush=True)

# 落盘
if hits:
    (OUT_DIR/f'hook_voice_xrefs_{ts}.json').write_text(json.dumps(hits, indent=2, ensure_ascii=False), encoding='utf-8')

os._exit(0)
