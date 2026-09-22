# hook_ab_forward.py — 受控 A/B：同图 → FTA vs 海鸟与鱼，只抓 phase 内快照并差分
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TARGET_TAGS = {'i+Ax', 'b0jW', 'WbWC'}
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
var TARGET = %s;

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
                        metaPtr: metaPtr, meta: meta, magicOff: i
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

var phase = 1;
var baseline = {};
var round = '';
var captures = {A: [], B: []};

Interceptor.attach(wx.base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var bk = '0x' + beginV.toString(16);
        if (phase === 1) { baseline[bk] = true; return; }
        if (!round) return;

        var info = readTag4(beginV);
        if (!info || TARGET.indexOf(info.tag4) < 0) return;

        var endV = args[2].toInt32() >>> 0;
        var sz = endV - beginV;
        var task = safeR(beginV, sz > 0 && sz <= 512 ? sz : 112);
        var payload = findPayload(info.meta);

        var rec = {
            ts: Date.now(),
            round: round,
            tag4: info.tag4,
            begin: bk,
            metaPtr: '0x' + info.metaPtr.toString(16),
            a3: '0x' + (args[3].toInt32() >>> 0).toString(16),
            task: task,
            meta: info.meta,
            payload: payload
        };
        captures[round].push(rec);
        send({t:'hit', round: round, tag4: info.tag4, begin: bk, n: captures[round].length});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'p2'}); });
recv('round', function(msg) { round = msg.payload.round; send({t:'round', round: round}); });
recv('dump', function(_) { send({t:'dump', captures: captures}); });
send({t:'ready'});
""" % json.dumps(list(TARGET_TAGS))

captures = {'A': [], 'B': []}
dump_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:250]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print('[+] Hook ready')
    elif t == 'p2':
        print('[+] Phase2 active')
    elif t == 'round':
        print(f'[+] Round {p["round"]} 开始捕获')
    elif t == 'hit':
        print(f'  ★ Round-{p["round"]} {p["tag4"]} begin={p["begin"]} #{p["n"]}')
    elif t == 'dump':
        captures.update(p.get('captures', {}))
        dump_ok[0] = True

def last_by_tag4(arr, tag4):
    for r in reversed(arr):
        if r.get('tag4') == tag4:
            return r
    return None

def u32_diff(a, b, label):
    a, b = bytes(a or []), bytes(b or [])
    n = min(len(a), len(b))
    diffs = []
    for off in range(0, n - 3, 4):
        va = struct.unpack_from('<I', a, off)[0]
        vb = struct.unpack_from('<I', b, off)[0]
        if va != vb:
            diffs.append((off, va, vb))
    print(f'\n[{label}] {len(diffs)} 处 u32 不同')
    for off, va, vb in diffs[:25]:
        skip = va in (0, 0xFFFFFFFF, FTA_P92) and vb in (0, 0xFFFFFFFF, FTA_P92)
        mark = '' if skip else ' ★'
        print(f'  +{off:3d}: {va:10d} (0x{va:08x}) → {vb:10d} (0x{vb:08x}){mark}')
    return diffs

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

print('[Phase1] 5s baseline...')
time.sleep(5)
sc.post({'type': 'phase2'})

print('\n' + '=' * 62)
print('  Round A — 请把【同一张图】转发到 FTA（文件传输助手）')
print('  你有 70 秒')
print('=' * 62)
sc.post({'type': 'round', 'payload': {'round': 'A'}})
t0 = time.time()
while time.time() - t0 < 70:
    time.sleep(0.5)

print('\n' + '=' * 62)
print('  Round B — 请把【同一张图】转发到「海鸟与鱼」')
print('  你有 70 秒')
print('=' * 62)
sc.post({'type': 'round', 'payload': {'round': 'B'}})
t1 = time.time()
while time.time() - t1 < 70:
    time.sleep(0.5)

sc.post({'type': 'round', 'payload': {'round': ''}})
sc.post({'type': 'dump'})
while not dump_ok[0]:
    time.sleep(0.2)

print(f'\n[捕获] Round-A: {len(captures["A"])}  Round-B: {len(captures["B"])}')

for tag4 in ['i+Ax', 'b0jW', 'WbWC']:
    ra = last_by_tag4(captures['A'], tag4)
    rb = last_by_tag4(captures['B'], tag4)
    if not ra or not rb:
        print(f'\n{tag4}: 缺少 A 或 B 快照 (A={bool(ra)} B={bool(rb)})')
        continue
    print(f'\n{"="*50}\n{tag4}  A.begin={ra["begin"]}  B.begin={rb["begin"]}')
    u32_diff(ra.get('meta'), rb.get('meta'), f'{tag4} meta')
    pa = bytes((ra.get('payload') or {}).get('bytes') or [])
    pb = bytes((rb.get('payload') or {}).get('bytes') or [])
    if pa and pb:
        u32_diff(pa, pb, f'{tag4} payload')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'ab_forward_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
