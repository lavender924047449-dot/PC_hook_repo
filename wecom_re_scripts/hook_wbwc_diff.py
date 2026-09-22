# hook_wbwc_diff.py — 捕获 WbWC 并与 FTA baseline 差分
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
BASELINE = OUT / 'dispatch_wbwc_20260911_185817.json'
FTA_P92 = 346833984

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
                        metaPtr: metaPtr
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

var hits = [];
var seen = {};

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var bk = '0x' + beginV.toString(16);
        if (seen[bk]) return;
        var info = readTag4(beginV);
        if (!info || info.tag4 !== 'WbWC') return;
        seen[bk] = true;
        var meta = safeR(info.metaPtr, 1024);
        var payload = findPayload(meta);
        hits.push({
            begin: bk,
            metaPtr: '0x' + info.metaPtr.toString(16),
            a3: '0x' + (args[3].toInt32() >>> 0).toString(16),
            task: safeR(beginV, 112),
            meta: meta,
            payload: payload
        });
        send({t:'hit', begin: bk, n: hits.length});
    }
});

recv('dump', function(_) { send({t:'dump', hits: hits}); });
send({t:'ready'});
"""

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
        print('[+] 监听 WbWC，90s...')
    elif p.get('t') == 'hit':
        print(f'  ★ WbWC #{p["n"]} begin={p["begin"]}')
    elif p.get('t') == 'dump':
        hits.extend(p.get('hits', []))
        dump_ok[0] = True

def diff_u32(a, b, label):
    a, b = bytes(a or []), bytes(b or [])
    n = min(len(a), len(b))
    diffs = []
    for off in range(0, n - 3, 4):
        va = struct.unpack_from('<I', a, off)[0]
        vb = struct.unpack_from('<I', b, off)[0]
        if va != vb:
            diffs.append((off, va, vb))
    print(f'\n[{label}] {len(diffs)} 处 u32 不同')
    for off, va, vb in diffs[:30]:
        print(f'  +{off:3d}: {va:10d} (0x{va:08x}) → {vb:10d} (0x{vb:08x})')

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()

print('\n>>> 若尚未完成转发，请在 90s 内：FTA 图片 →「海鸟与鱼」<<<')
t0 = time.time()
while time.time() - t0 < 90:
    time.sleep(0.5)

sc.post({'type': 'dump'})
t1 = time.time()
while not dump_ok[0] and time.time() - t1 < 5:
    time.sleep(0.2)

base_pb = []
if BASELINE.exists():
    bl = json.loads(BASELINE.read_text(encoding='utf-8'))
    if bl:
        base_pb = bytes((bl[0].get('payload') or {}).get('bytes') or [])
        print(f'\n[FTA baseline] payload+92 = {FTA_P92} (0x{FTA_P92:08x})')

print(f'\n[结果] 捕获 {len(hits)} 个 WbWC')
for i, h in enumerate(hits):
    pb = bytes((h.get('payload') or {}).get('bytes') or [])
    p92 = struct.unpack_from('<I', pb, 92)[0] if len(pb) >= 96 else None
    print(f'\n--- #{i+1} begin={h["begin"]} ---')
    if p92 is not None:
        changed = '✓ 变化' if p92 != FTA_P92 else '✗ 未变'
        print(f'  payload+92 = {p92} (0x{p92:08x})  [{changed} vs FTA]')
    if base_pb and pb:
        diff_u32(base_pb, pb, 'payload FTA→海鸟与鱼')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'wbwc_hainiao_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
