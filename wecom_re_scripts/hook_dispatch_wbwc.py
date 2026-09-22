# hook_dispatch_wbwc.py — WbWC 转发：扩展 EBP 链 + 完整 task/metadata/payload dump
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('WXWork :9882 not found')

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
var size = wx.size;

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

function readTag4(beginV) {
    try {
        var metaPtr = ptr(beginV).add(52).readU32() >>> 0;
        var m = new Uint8Array(ptr(metaPtr).readByteArray(512));
        for (var i = 0; i < m.length - 3; i++) {
            if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                if (i + 28 <= m.length) {
                    return {
                        tag4: String.fromCharCode(m[i+24], m[i+25], m[i+26], m[i+27]),
                        metaPtr: metaPtr,
                        magicOff: i
                    };
                }
            }
        }
    } catch(e) {}
    return null;
}

function ebpChain(ctx, maxN) {
    var out = [];
    try {
        var fp = ctx.ebp;
        for (var i = 0; i < maxN; i++) {
            if (!fp || fp.isNull()) break;
            var ret = fp.add(4).readPointer();
            var rva = ret.sub(base).toInt32() >>> 0;
            if (rva > 0 && rva < size) out.push('0x' + rva.toString(16));
            fp = fp.readPointer();
        }
    } catch(e) {}
    return out;
}

var hits = [];
var seen = {};

function captureFromCgi(args, ctx, src) {
    var beginV = args[1].toInt32() >>> 0;
    var endV = args[2].toInt32() >>> 0;
    var bk = '0x' + beginV.toString(16);
    if (seen[bk]) return;
    var info = readTag4(beginV);
    if (!info || info.tag4 !== 'WbWC') return;
    seen[bk] = true;

    var sz = endV - beginV;
    var task = safeR(beginV, sz > 0 && sz <= 512 ? sz : 112);
    var meta = safeR(info.metaPtr, 1024);

    var payload = null;
    if (meta) {
        for (var off = 120; off < Math.min(meta.length, 512); off += 4) {
            var pv = (meta[off])|(meta[off+1]<<8)|(meta[off+2]<<16)|(meta[off+3]<<24);
            pv = pv >>> 0;
            if (pv > 0x10000000 && pv < 0x7F000000) {
                var pb = safeR(pv, 256);
                if (pb && pb[0]===0x4c && pb[1]===0x43 && pb[2]===0x79 && pb[3]===0x0b) {
                    payload = {ptr: '0x'+pv.toString(16), bytes: pb};
                    break;
                }
            }
        }
    }

    hits.push({
        src: src,
        begin: bk,
        end: '0x' + endV.toString(16),
        a0: '0x' + (args[0].toInt32() >>> 0).toString(16),
        a3: '0x' + (args[3].toInt32() >>> 0).toString(16),
        metaPtr: '0x' + info.metaPtr.toString(16),
        chain20: ebpChain(ctx, 20),
        task: task,
        meta: meta,
        payload: payload
    });
    send({t:'hit', begin: bk, src: src, chain: hits[hits.length-1].chain20.length});
}

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) { captureFromCgi(args, this.context, '0x390CE0'); }
});

Interceptor.attach(base.add(0x44aaa0), {
    onEnter: function(args) {
        send({t:'dispatch', a0: args[0].toString(), chain8: ebpChain(this.context, 8)});
    }
});

recv('dump', function(_) { send({t:'dump', hits: hits}); });
send({t:'ready'});
"""

hits = []
dump_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:300]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print('[+] Hook 0x390CE0 + 0x44AAA0 ready')
    elif p.get('t') == 'dispatch':
        pass  # noisy
    elif p.get('t') == 'hit':
        print(f'  ★ WbWC @ {p["src"]} begin={p["begin"]} chain={p["chain"]} frames')
    elif p.get('t') == 'dump':
        hits.extend(p.get('hits', []))
        dump_ok[0] = True

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

print('\n' + '=' * 60)
print('>>> 请在 90 秒内再转发 1 条消息（扩展 caller 链捕获）<<<')
print('=' * 60)

t0 = time.time()
while time.time() - t0 < 90:
    time.sleep(0.5)

sc.post({'type': 'dump'})
t1 = time.time()
while not dump_ok[0] and time.time() - t1 < 5:
    time.sleep(0.2)

print(f'\n[结果] WbWC 完整 dump: {len(hits)} 个')
for h in hits:
    print(f'  begin={h["begin"]} chain20={h.get("chain20",[])}')
    pl = h.get('payload') or {}
    if pl.get('bytes'):
        b = bytes(pl['bytes'])
        if len(b) >= 96:
            conv = struct.unpack_from('<I', b, 92)[0]
            print(f'    payload+92 conv_candidate={conv} (0x{conv:08x})')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'dispatch_wbwc_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
