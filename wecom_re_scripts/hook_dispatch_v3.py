# hook_dispatch_v3.py — ring buffer 回溯：WbWC 触发时关联之前 0x44AAA0 链快照
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
KNOWN = {346833984, 193405740, 336445, 182298680, 194741676, 0, 0xFFFFFFFF}
RVAS = ['0x44aaa0', '0x449fa7', '0x44aacd', '0x4493f2']

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;

function safeR(p, n) {
    try { return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e) { return null; }
}

function readTag4(beginV) {
    try {
        var metaPtr = ptr(beginV).add(52).readU32() >>> 0;
        var m = new Uint8Array(ptr(metaPtr).readByteArray(256));
        for (var i = 0; i < m.length - 3; i++) {
            if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                if (i + 28 <= m.length) {
                    return String.fromCharCode(m[i+24], m[i+25], m[i+26], m[i+27]);
                }
            }
        }
    } catch(e) {}
    return null;
}

function ebpFrames(ctx) {
    var out = [];
    try {
        var fp = ctx.ebp;
        for (var i = 0; i < 12; i++) {
            if (!fp || fp.isNull()) break;
            var fr = safeR(fp, 8);
            if (!fr) break;
            var ret = ((fr[4])|(fr[5]<<8)|(fr[6]<<16)|(fr[7]<<24)) >>> 0;
            out.push({i:i, ebp:'0x'+fp.toInt32().toString(16), ret:'0x'+ret.toString(16),
                      stack: safeR(fp.sub(64), 256)});
            fp = ptr((fr[0])|(fr[1]<<8)|(fr[2]<<16)|(fr[3]<<24));
        }
    } catch(e) {}
    return out;
}

function snapFn(fnRva, ctx, args) {
    var ecx = ctx.ecx.toInt32() >>> 0;
    var argVals = [], argBytes = [];
    for (var i = 0; i < 6; i++) {
        try {
            var v = args[i].toInt32() >>> 0;
            argVals.push('0x' + v.toString(16));
            argBytes.push(safeR(args[i], 512));
        } catch(e) { argVals.push('?'); argBytes.push(null); }
    }
    return {
        ts: Date.now(),
        fn: fnRva,
        ecx: '0x' + ecx.toString(16),
        args: argVals,
        thisData: safeR(ecx, 2048),
        argBytes: argBytes,
        frames: ebpFrames(ctx),
        espDump: safeR(ctx.esp, 512)
    };
}

var ring = [];
var MAX_RING = 80;
var correlated = [];

function pushRing(s) {
    ring.push(s);
    if (ring.length > MAX_RING) ring.shift();
}

function correlateFromWbwc(tag, begin) {
    var now = Date.now();
    var picked = [];
    for (var i = ring.length - 1; i >= 0; i--) {
        if (now - ring[i].ts > 5000) break;
        picked.push(ring[i]);
    }
    correlated.push({
        wbwcTs: now,
        tag: tag,
        begin: begin,
        chain: picked.reverse()
    });
    send({t:'corr', tag: tag, begin: begin, chainLen: picked.length, n: correlated.length});
}

['0x44aaa0','0x449fa7','0x44aacd','0x4493f2'].forEach(function(rva) {
    Interceptor.attach(base.add(parseInt(rva, 16)), {
        onEnter: function(args) {
            pushRing(snapFn(rva, this.context, args));
        }
    });
});

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var tag = readTag4(beginV);
        if (tag === 'WbWC') {
            correlateFromWbwc(tag, '0x' + beginV.toString(16));
        }
    }
});

recv('dump', function(_) { send({t:'dump', ring: ring, correlated: correlated}); });
send({t:'ready'});
""" 

correlated = []
ring = []
dump_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:250]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print('[+] ring buffer + WbWC correlate ready')
    elif p.get('t') == 'corr':
        print(f'  ★ CORR #{p["n"]} {p["tag"]} begin={p["begin"]} chain={p["chainLen"]} frames')
    elif p.get('t') == 'dump':
        correlated.extend(p.get('correlated', []))
        ring.extend(p.get('ring', []))
        dump_ok[0] = True

def collect_u32(blob):
    bs = bytes(blob or [])
    out = []
    for off in range(0, len(bs) - 3, 4):
        v = struct.unpack_from('<I', bs, off)[0]
        if v not in KNOWN and 100000 < v < 0x7FFFFFFF:
            out.append((off, v))
    return out

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

print('\n>>> 90s 内请转发 1 次（FTA → 海鸟与鱼 或任意目标）<<<\n')
t0 = time.time()
while time.time() - t0 < 90:
    time.sleep(0.5)

sc.post({'type': 'dump'})
while not dump_ok[0]:
    time.sleep(0.2)

print(f'\n[结果] WbWC 关联 {len(correlated)} 次, ring={len(ring)}')

all_cands = Counter()
for i, corr in enumerate(correlated):
    print(f'\n=== CORR #{i+1} begin={corr["begin"]} chain={len(corr.get("chain",[]))} ===')
    for snap in corr.get('chain', []):
        fn = snap.get('fn')
        print(f'  {fn} ecx={snap.get("ecx")} args={snap.get("args",[])[:4]}')
        for label, key in [('this', 'thisData'), ('esp', 'espDump')]:
            for off, v in collect_u32(snap.get(key))[:6]:
                all_cands[v] += 1
                print(f'    {label}+0x{off:03x}: {v} (0x{v:08x})')
        for ab in snap.get('argBytes') or []:
            for off, v in collect_u32(ab)[:4]:
                all_cands[v] += 1
        for fr in snap.get('frames') or []:
            for off, v in collect_u32(fr.get('stack'))[:3]:
                all_cands[v] += 1

print('\n[top u32 候选]')
for v, n in all_cands.most_common(20):
    print(f'  {v:10d} (0x{v:08x}) ×{n}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'dispatch_v3_{ts}.json'
out.write_text(json.dumps({'correlated': correlated, 'ringSize': len(ring)}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
