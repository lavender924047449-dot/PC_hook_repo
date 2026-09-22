# hook_all_tag4_fwd.py — 转发时捕获全部 tag4（不过滤 WbWC）
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
FTA_P92 = 346833984

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

var phase = 1;
var baseline = {};
var hits = [];

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        if (phase === 1) return;
        var beginV = args[1].toInt32() >>> 0;
        var info = readTag4(beginV);
        if (!info) return;
        var meta = safeR(info.metaPtr, 1024);
        var payload = findPayload(meta);
        var p92 = null;
        if (payload && payload.bytes.length >= 96) {
            var b = payload.bytes;
            p92 = (b[92])|(b[93]<<8)|(b[94]<<16)|(b[95]<<24);
            p92 = p92 >>> 0;
        }
        hits.push({
            ts: Date.now(),
            tag4: info.tag4,
            begin: '0x' + beginV.toString(16),
            metaPtr: '0x' + info.metaPtr.toString(16),
            p92: p92,
            a3: '0x' + (args[3].toInt32() >>> 0).toString(16)
        });
        send({t:'hit', tag4: info.tag4, begin: '0x'+beginV.toString(16), p92: p92});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go'}); });
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
        print('[+] ready')
    elif p.get('t') == 'go':
        print('[+] Phase2 — 请转发')
    elif p.get('t') == 'hit':
        p92 = p.get('p92')
        ps = f' p92={p92} (0x{p92:08x})' if p92 is not None else ''
        mark = ' ★NEW' if p92 and p92 != FTA_P92 else ''
        print(f'  {p["tag4"]:6s} begin={p["begin"]}{ps}{mark}')
    elif p.get('t') == 'dump':
        hits.extend(p.get('hits', []))
        dump_ok[0] = True

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)
print('[Phase1] 5s baseline skip...')
time.sleep(5)
sc.post({'type': 'phase2'})

print('\n>>> 90s 内请再转发 1 次：FTA 图片 →「海鸟与鱼」<<<\n')
t0 = time.time()
while time.time() - t0 < 90:
    time.sleep(0.5)

sc.post({'type': 'dump'})
while not dump_ok[0]:
    time.sleep(0.2)

print(f'\n[总计] {len(hits)} 事件')
print('tag4:', Counter(h['tag4'] for h in hits))
new_p92 = sorted({h['p92'] for h in hits if h.get('p92') and h['p92'] != FTA_P92})
print(f'非 FTA 的 p92 值: {new_p92}')
for v in new_p92:
    tags = [h['tag4'] for h in hits if h.get('p92')==v]
    print(f'  p92={v} (0x{v:08x}) tag4={Counter(tags)}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'all_tag4_fwd_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] {out}')

sc.unload()
sess.detach()
os._exit(0)
