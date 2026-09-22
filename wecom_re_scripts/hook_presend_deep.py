# hook_presend_deep.py — 深度 dump PreSendNewMessage args
# args[1] = MessageObject: dump 前 2KB + 追 2 层指针（每层 1KB）
# args[0/2/3] = task/context: 各 dump 512B + 追 1 层
# 全部原始 hex 落盘，方便离线找 msgtype/text/proto

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var hookPtr = mod.base.add(0x919ffb2);
var n = 0, MAX = 8;

function safeBytes(a, sz) {
    try { var p = ptr(a); var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s = '';
    for (var i=0; i<a.length; i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function u32(a, i) { return ((a[i]|(a[i+1]<<8)|(a[i+2]<<16)|(a[i+3]<<24))>>>0); }
function asciiStrs(ab, minLen) {
    minLen = minLen || 4;
    var a = new Uint8Array(ab), out = [], run = '', st = 0;
    for (var i=0; i<a.length; i++) {
        if (a[i] >= 0x20 && a[i] <= 0x7E) {
            if (!run.length) st = i; run += String.fromCharCode(a[i]);
        } else {
            if (run.length >= minLen) out.push({o:st, s:run});
            run = '';
        }
    }
    if (run.length >= minLen) out.push({o:st, s:run});
    return out;
}
// 前 128 个 dword 里筛 heap ptr（去重）
function heapPtrs(ab, limit) {
    var a = new Uint8Array(ab), out = [], seen = {};
    for (var i=0; i+3<a.length && out.length<(limit||64); i+=4) {
        var pv = u32(a, i);
        if (pv > 0x00400000 && pv < 0x7F000000) {
            var k = pv.toString(16);
            if (!seen[k]) { seen[k]=1; out.push({off:i, p:pv}); }
        }
    }
    return out;
}

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (n >= MAX) return;
        n++;

        var pkg = { n: n, args: {} };

        // 4 个参数逐个处理
        for (var ai=0; ai<4; ai++) {
            var av = args[ai].toUInt32();
            var depth = (ai === 1) ? 2 : 1;
            var l1Size = (ai === 1) ? 2048 : 512;
            var l2Size = 1024;

            var raw = safeBytes(av, l1Size);
            if (!raw) { pkg.args[ai] = {addr: '0x'+av.toString(16), null: true}; continue; }

            var strs = asciiStrs(raw, 4).slice(0, 20);
            var ptrs = heapPtrs(raw, 32);

            // L2: 追一层
            var l2 = [];
            if (depth >= 2) {
                for (var pi=0; pi<ptrs.length && pi<24; pi++) {
                    var p2v = ptrs[pi].p;
                    var raw2 = safeBytes(p2v, l2Size);
                    if (!raw2) continue;
                    var strs2 = asciiStrs(raw2, 4).slice(0, 8);
                    var ptrs2 = heapPtrs(raw2, 16).slice(0, 12);
                    l2.push({
                        parent_off: ptrs[pi].off, addr: '0x'+p2v.toString(16),
                        hex: toHex(raw2),
                        strs: strs2,
                        ptrs: ptrs2.map(function(x){return {off:x.off, p:'0x'+x.p.toString(16)};})
                    });
                }
            }

            pkg.args[ai] = {
                addr: '0x'+av.toString(16),
                hex: toHex(raw),
                strs: strs,
                ptrs: ptrs.map(function(x){return {off:x.off, p:'0x'+x.p.toString(16)};}),
                l2: l2
            };
        }

        var bt = [];
        try { bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,5).map(function(a){return a.toString();}); } catch(e){}
        pkg.bt = bt;
        pkg.esp = this.context.esp.toString();
        pkg.ebp = this.context.ebp.toString();

        send(pkg);
    }
});

send({t:'ready'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

hits = []
def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    if p.get('t') == 'ready': print('[+] Hook armed', flush=True); return

    hits.append(p)
    # 立刻落盘 ndjson
    with (OUT_DIR/f'hook_presend_deep_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    # 每 arg 的 hex 单独落盘（便于 hex dump 分析）
    for ai in ['0','1','2','3']:
        a = p['args'].get(ai)
        if a and a.get('hex'):
            fn = OUT_DIR / f'hook_presend_deep_{ts}_h{p["n"]}_a{ai}.bin'
            fn.write_bytes(bytes.fromhex(a['hex']))
        for li, l2 in enumerate(a.get('l2', []) if a else []):
            fn2 = OUT_DIR / f'hook_presend_deep_{ts}_h{p["n"]}_a{ai}_l2_{li:02d}_{l2["addr"]}.bin'
            fn2.write_bytes(bytes.fromhex(l2['hex']))

    # 精简打印
    print(f'\n{"="*72}\n★ HIT #{p["n"]}  bt={p["bt"][:3]}', flush=True)
    for ai_i in range(4):
        a = p['args'].get(str(ai_i))
        if not a: continue
        strs_prev = ', '.join([f'@{s["o"]:03x}:{s["s"][:30]!r}' for s in a.get('strs', [])[:5]])
        print(f'  args[{ai_i}] = {a["addr"]}', flush=True)
        print(f'    L1 strs: {strs_prev}', flush=True)
        if a.get('l2'):
            print(f'    L2 ({len(a["l2"])} ptrs):', flush=True)
            for l2 in a['l2'][:8]:
                l2s = ', '.join([f'@{s["o"]:03x}:{s["s"][:30]!r}' for s in l2.get('strs', [])[:3]])
                print(f'      +0x{l2["parent_off"]:03x}→{l2["addr"]}: {l2s}', flush=True)

print('[*] PID...', flush=True)
pid = get_pid(); print(f'    PID={pid}', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS); sc.on('message', on_msg); sc.load()

import time
print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内：\n    1. 向 FTA 发一条文字（区分类型）\n    2. 向某个客户/群 发一条文字（不同 conversationId）\n    3. 向 FTA 发一个文件\n', flush=True)
time.sleep(CAPTURE_SEC)
sc.unload(); sess.detach()
print(f'\n[+] 共 {len(hits)} 次 HIT，产物见 hook_presend_deep_{ts}_*', flush=True)
os._exit(0)
