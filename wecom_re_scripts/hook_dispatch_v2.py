# hook_dispatch_v2.py — WbWC 触发后 dump 0x44AAA0/449FA7/44AACD 栈与对象，搜 dest conv_id
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
KNOWN = {346833984, 193405740, 336445, 0, 0xFFFFFFFF}
HOOKS = [0x44aaa0, 0x449fa7, 0x44aacd, 0x4493f2]

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

function ebpFrames(ctx, maxN) {
    var out = [];
    try {
        var fp = ctx.ebp;
        for (var i = 0; i < maxN; i++) {
            if (!fp || fp.isNull()) break;
            var fr = safeR(fp, 8);
            if (!fr) break;
            var ret = (fr[4])|(fr[5]<<8)|(fr[6]<<16)|(fr[7]<<24);
            ret = ret >>> 0;
            var rva = ret - base.toInt32();
            if (rva < 0) rva = ret;
            var stack = safeR(fp.sub(128), 384);
            out.push({
                i: i,
                ebp: '0x' + fp.toInt32().toString(16),
                ret: '0x' + ret.toString(16),
                rva: '0x' + (ret >>> 0).toString(16),
                stack: stack
            });
            fp = ptr((fr[0])|(fr[1]<<8)|(fr[2]<<16)|(fr[3]<<24));
        }
    } catch(e) {}
    return out;
}

function ptrScan(bs, maxN) {
    var out = [];
    if (!bs) return out;
    for (var off = 0; off + 3 < Math.min(bs.length, 512); off += 4) {
        var pv = (bs[off])|(bs[off+1]<<8)|(bs[off+2]<<16)|(bs[off+3]<<24);
        pv = pv >>> 0;
        if (pv > 0x10000000 && pv < 0x7F000000) {
            var d = safeR(pv, 512);
            if (d) out.push({off: off, ptr: '0x'+pv.toString(16), bytes: d});
            if (out.length >= maxN) break;
        }
    }
    return out;
}

var armedUntil = 0;
var lastWbwc = 0;
var caps = [];
var capKeys = {};

function armWindow() {
    armedUntil = Date.now() + 800;
}

function maybeCap(fnRva, ctx, args) {
    if (Date.now() > armedUntil) return;
    var key = fnRva + '|' + lastWbwc;
    if (capKeys[key]) return;
    capKeys[key] = true;

    var ecx = ctx.ecx.toInt32() >>> 0;
    var argVals = [], argBytes = [];
    for (var i = 0; i < 6; i++) {
        try {
            var v = args[i].toInt32() >>> 0;
            argVals.push('0x' + v.toString(16));
            argBytes.push(safeR(args[i], 512));
        } catch(e) {
            argVals.push('?');
            argBytes.push(null);
        }
    }
    var thisData = safeR(ecx, 2048);
    caps.push({
        fn: fnRva,
        wbwcTs: lastWbwc,
        ecx: '0x' + ecx.toString(16),
        args: argVals,
        thisData: thisData,
        thisPtrs: ptrScan(thisData, 24),
        argPtrs: argBytes.map(function(b, i) {
            return b ? ptrScan(b, 8).map(function(p){ p.fromArg=i; return p; }) : [];
        }).reduce(function(a,b){ return a.concat(b); }, []),
        frames: ebpFrames(ctx, 16),
        espDump: safeR(ctx.esp, 512)
    });
    send({t:'cap', fn: fnRva, n: caps.length});
}

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var tag = readTag4(beginV);
        if (tag === 'WbWC' || tag === 'b0jW') {
            lastWbwc = Date.now();
            armWindow();
            send({t:'wbwc', tag: tag, begin: '0x'+beginV.toString(16)});
        }
    }
});

['0x44aaa0','0x449fa7','0x44aacd','0x4493f2'].forEach(function(rva) {
    Interceptor.attach(base.add(parseInt(rva, 16)), {
        onEnter: function(args) {
            maybeCap(rva, this.context, args);
        }
    });
});

recv('dump', function(_) { send({t:'dump', caps: caps}); });
send({t:'ready'});
"""

caps = []
dump_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:250]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print('[+] dispatch chain hooks ready')
    elif p.get('t') == 'wbwc':
        print(f'  ⚡ {p["tag"]} begin={p["begin"]} → arm 800ms')
    elif p.get('t') == 'cap':
        print(f'  ★ CAP #{p["n"]} @ {p["fn"]}')
    elif p.get('t') == 'dump':
        caps.extend(p.get('caps', []))
        dump_ok[0] = True

def collect_u32(blob):
    out = []
    bs = bytes(blob or [])
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

print('\n' + '=' * 60)
print('>>> 90s 内请转发 1 次（建议 FTA 图片 →「海鸟与鱼」）<<<')
print('=' * 60)
t0 = time.time()
while time.time() - t0 < 90:
    time.sleep(0.5)

sc.post({'type': 'dump'})
while not dump_ok[0]:
    time.sleep(0.2)

print(f'\n[结果] 捕获 {len(caps)} 个 dispatch 快照')
all_cands = Counter()
for c in caps:
    print(f'\n--- {c["fn"]} ecx={c["ecx"]} ---')
    for label, blob in [('this', c.get('thisData')), ('esp', c.get('espDump'))]:
        found = collect_u32(blob)
        for off, v in found[:8]:
            all_cands[v] += 1
            print(f'  {label}+0x{off:03x}: {v} (0x{v:08x})')
    for fr in c.get('frames', [])[:4]:
        found = collect_u32(fr.get('stack'))
        for off, v in found[:5]:
            all_cands[v] += 1

print('\n[高频 u32 候选 top15]')
for v, n in all_cands.most_common(15):
    print(f'  {v:10d} (0x{v:08x}) ×{n}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'dispatch_v2_{ts}.json'
out.write_text(json.dumps(caps, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
