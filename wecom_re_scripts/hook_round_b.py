# hook_round_b.py — 仅捕获 WbWC/b0jW，用于 Round B（海鸟与鱼）
import frida, subprocess, sys, os, time, json, struct, hashlib
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
AB_A = OUT / 'ab_forward_20260911_192006.json'
FTA_P92 = 346833984
TAGS = {'WbWC', 'b0jW'}

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
var TAGS = %s;

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

function readTag4(beginV) {
    try {
        var metaPtr = ptr(beginV).add(52).readU32() >>> 0;
        var meta = safeR(metaPtr, 1024);
        if (!meta) return null;
        for (var i = 0; i < meta.length - 3; i++) {
            if (meta[i]===0xd0 && meta[i+1]===0x07 && meta[i+2]===0x00 && meta[i+3]===0x02) {
                if (i + 28 <= meta.length) {
                    return {
                        tag4: String.fromCharCode(meta[i+24], meta[i+25], meta[i+26], meta[i+27]),
                        metaPtr: metaPtr, meta: meta
                    };
                }
            }
        }
    } catch(e) {}
    return null;
}

function findPayload(meta) {
    if (!meta) return null;
    for (var off = 120; off < Math.min(meta.length, 512); off += 4) {
        var pv = (meta[off])|(meta[off+1]<<8)|(meta[off+2]<<16)|(meta[off+3]<<24);
        pv = pv >>> 0;
        if (pv > 0x10000000 && pv < 0x7F000000) {
            var pb = safeR(pv, 256);
            if (pb && pb[0]===0x4c && pb[1]===0x43 && pb[2]===0x79 && pb[3]===0x0b)
                return {ptr: '0x'+pv.toString(16), bytes: pb};
        }
    }
    return null;
}

var lastHash = {};
var hits = [];

Interceptor.attach(wx.base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var info = readTag4(beginV);
        if (!info || TAGS.indexOf(info.tag4) < 0) return;

        var endV = args[2].toInt32() >>> 0;
        var sz = endV - beginV;
        var task = safeR(beginV, sz > 0 && sz <= 512 ? sz : 112);
        var payload = findPayload(info.meta);
        var key = info.tag4 + '|' + beginV;
        var snap = JSON.stringify({m: info.meta, t: task, p: payload});
        var h = snap.length + '_' + (info.meta ? info.meta[92] : 0);
        if (lastHash[key] === h) return;
        lastHash[key] = h;

        hits.push({
            ts: Date.now(),
            tag4: info.tag4,
            begin: '0x' + beginV.toString(16),
            metaPtr: '0x' + info.metaPtr.toString(16),
            task: task,
            meta: info.meta,
            payload: payload
        });
        send({t:'hit', tag4: info.tag4, begin: '0x'+beginV.toString(16), n: hits.length});
    }
});

recv('dump', function(_) { send({t:'dump', hits: hits}); });
send({t:'ready'});
""" % json.dumps(list(TAGS))

hits = []
dump_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print('[+] 仅 WbWC/b0jW，60s — 请转发到「海鸟与鱼」')
    elif p.get('t') == 'hit':
        print(f'  ★ {p["tag4"]} begin={p["begin"]} #{p["n"]}')
    elif p.get('t') == 'dump':
        hits.extend(p.get('hits', []))
        dump_ok[0] = True

def last_tag(arr, tag4):
    for r in reversed(arr):
        if r.get('tag4') == tag4:
            return r
    return None

def u32_diff(a, b, label):
    a, b = bytes(a or []), bytes(b or [])
    diffs = []
    for off in range(0, min(len(a), len(b)) - 3, 4):
        va = struct.unpack_from('<I', a, off)[0]
        vb = struct.unpack_from('<I', b, off)[0]
        if va != vb:
            diffs.append((off, va, vb))
    print(f'\n[{label}] {len(diffs)} 处不同')
    for off, va, vb in diffs[:20]:
        mark = ' ★' if va not in (0, FTA_P92, 0xFFFFFFFF) or vb not in (0, FTA_P92, 0xFFFFFFFF) else ''
        print(f'  +{off:3d}: {va} (0x{va:08x}) → {vb} (0x{vb:08x}){mark}')
    return diffs

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
t0 = time.time()
while time.time() - t0 < 60:
    time.sleep(0.5)
sc.post({'type': 'dump'})
while not dump_ok[0]:
    time.sleep(0.2)

print(f'\n[Round B] 捕获 {len(hits)} 个唯一快照')

# 与 Round A 最后 WbWC 对比
if AB_A.exists():
    ab = json.loads(AB_A.read_text(encoding='utf-8'))
    wb_a = [x for x in ab['A'] if x['tag4'] == 'WbWC']
    ra = wb_a[-1] if wb_a else None
    rb = last_tag(hits, 'WbWC')
    if ra and rb:
        print('\n=== Round-A(FTA) vs Round-B(海鸟与鱼) WbWC ===')
        u32_diff(ra.get('meta'), rb.get('meta'), 'meta')
        pa = bytes((ra.get('payload') or {}).get('bytes') or [])
        pb = bytes((rb.get('payload') or {}).get('bytes') or [])
        if pa and pb:
            u32_diff(pa, pb, 'payload')
    else:
        print(f'对比跳过: Round-A WbWC={bool(ra)} Round-B WbWC={bool(rb)}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'round_b_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')
sc.unload()
sess.detach()
os._exit(0)
