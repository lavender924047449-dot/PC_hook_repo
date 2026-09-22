# hook_449fa7_ab.py — WbWC/b0jW 触发，回溯 449FA7 args[1]，A=FTA B=海鸟与鱼
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
FTA_SRC = 346833984

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

function snap449(args) {
    return {
        ts: Date.now(),
        args: [0,1,2,3].map(function(i){ try{return '0x'+(args[i].toInt32()>>>0).toString(16);}catch(e){return '?';} }),
        arg0: safeR(args[0], 512),
        arg1: safeR(args[1], 1024),
        arg2: safeR(args[2], 512)
    };
}

var ring449 = [];
var round = '';
var results = {A: null, B: null};

function pick449(wbwcTs) {
    var best = null;
    for (var i = ring449.length - 1; i >= 0; i--) {
        var s = ring449[i];
        if (wbwcTs - s.ts > 15000) break;
        if (s.ts <= wbwcTs) { best = s; break; }
    }
    if (!best && ring449.length) best = ring449[ring449.length - 1];
    return best;
}

Interceptor.attach(base.add(0x449fa7), {
    onEnter: function(args) {
        ring449.push(snap449(args));
        if (ring449.length > 40) ring449.shift();
    }
});

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        if (!round || results[round]) return;
        var beginV = args[1].toInt32() >>> 0;
        var tag = readTag4(beginV);
        if (tag !== 'WbWC' && tag !== 'b0jW') {
            if (round && !results[round]) send({t:'tag', round: round, tag: tag || '(null)'});
            return;
        }
        var now = Date.now();
        var s449 = pick449(now);
        if (!s449) {
            send({t:'miss', round: round, tag: tag, ring: ring449.length});
            return;
        }
        results[round] = Object.assign({
            wbwcBegin: '0x' + beginV.toString(16),
            tag: tag,
            deltaMs: now - s449.ts
        }, s449);
        send({t:'got', round: round, tag: tag, begin: '0x'+beginV.toString(16), delta: now - s449.ts});
    }
});

recv('set_round', function(msg) {
    round = msg.payload.id || '';
    send({t:'round', id: round});
});
recv('dump', function(_) { send({t:'dump', results: results}); });
send({t:'ready'});
"""

results = {'A': None, 'B': None}
dump_ok = [False]
captured = {'A': False, 'B': False}

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print('[+] ready — 449FA7 ring + WbWC/b0jW trigger')
    elif p.get('t') == 'round':
        print(f'\n{"="*62}\n[Round {p["id"]}] 请在 90s 内完成转发\n{"="*62}', flush=True)
    elif p.get('t') == 'tag':
        print(f'  · Round-{p["round"]} tag4={p["tag"]}', flush=True)
    elif p.get('t') == 'miss':
        print(f'  ⚠ Round-{p["round"]} {p["tag"]} 但 ring449 空 (len={p["ring"]})', flush=True)
    elif p.get('t') == 'got':
        captured[p['round']] = True
        print(f'  ★ Round-{p["round"]} {p["tag"]} begin={p["begin"]} (449FA7 Δ{p["delta"]}ms)')
    elif p.get('t') == 'dump':
        results.update(p.get('results', {}))
        dump_ok[0] = True

def scan_conv_u32(bs):
    out = []
    for off in range(0, len(bs) - 3, 4):
        v = struct.unpack_from('<I', bs, off)[0]
        if 340000000 < v < 350000000:
            out.append((off, v))
    return out

def diff_arg1(a, b):
    ba, bb = bytes(a or []), bytes(b or [])
    diffs = []
    for off in range(0, min(len(ba), len(bb)) - 3, 4):
        va = struct.unpack_from('<I', ba, off)[0]
        vb = struct.unpack_from('<I', bb, off)[0]
        if va != vb:
            diffs.append((off, va, vb))
    return diffs

def run_round(sc, rid, label):
    print(f'\n>>> Round {rid}: 同一张图 → {label} <<<')
    sc.post({'type': 'set_round', 'payload': {'id': rid}})
    time.sleep(0.3)
    t0 = time.time()
    while time.time() - t0 < 90 and not captured.get(rid):
        time.sleep(0.3)
    if captured.get(rid):
        print(f'  [OK] Round {rid} 已捕获')
    else:
        print(f'  [!] Round {rid} 超时未捕获')

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

run_round(sc, 'A', 'FTA（文件传输助手）')
run_round(sc, 'B', '「海鸟与鱼」')

sc.post({'type': 'dump'})
t2 = time.time()
while not dump_ok[0] and time.time() - t2 < 10:
    time.sleep(0.2)

for rnd, label in [('A', 'FTA'), ('B', '海鸟与鱼')]:
    r = results.get(rnd)
    print(f'\n--- Round {rnd} ({label}) ---')
    if not r:
        print('  未捕获')
        continue
    print(f'  tag={r.get("tag")} 449FA7 args={r.get("args")} delta={r.get("deltaMs")}ms')
    for off, v in scan_conv_u32(bytes(r.get('arg1') or [])):
        print(f'  arg1+{off:3d}: {v} (0x{v:08x})' + (' ←FTA-src' if v == FTA_SRC else ''))

ra, rb = results.get('A'), results.get('B')
if ra and rb:
    print('\n=== arg1 差分 (FTA vs 海鸟与鱼) ★=346M conv 空间 ===')
    for off, va, vb in diff_arg1(ra.get('arg1'), rb.get('arg1')):
        mark = ' ★' if (340000000 < va < 350000000) or (340000000 < vb < 350000000) else ''
        print(f'  +{off:3d}: {va} → {vb}{mark}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'arg1_ab_{ts}.json'
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')
sc.unload()
sess.detach()
os._exit(0)
