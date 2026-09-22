# hook_tag4_deep.py — 深度 dump 转发相关 tag4: i+Ax / b0jW / WbWC
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

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
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
                    var tag4 = String.fromCharCode(meta[i+24], meta[i+25], meta[i+26], meta[i+27]);
                    return {tag4: tag4, metaPtr: metaPtr, meta: meta, magicOff: i};
                }
            }
        }
    } catch(e) {}
    return null;
}

function deepPtrs(meta) {
    var deep = [];
    if (!meta) return deep;
    for (var off = 0; off < Math.min(meta.length, 512); off += 4) {
        var pv = (meta[off])|(meta[off+1]<<8)|(meta[off+2]<<16)|(meta[off+3]<<24);
        pv = pv >>> 0;
        if (pv > 0x10000000 && pv < 0x7F000000) {
            var d = safeR(pv, 512);
            if (d) deep.push({fromOff: off, ptr: '0x'+pv.toString(16), bytes: d});
        }
    }
    return deep;
}

var phase = 1;
var baseline = {};
var results = [];

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var bk = '0x' + beginV.toString(16);
        if (phase === 1) { baseline[bk] = true; return; }
        if (baseline[bk]) return;
        if (results.some(function(r){ return r.begin === bk; })) return;

        var info = readTag4(beginV);
        if (!info || TARGET.indexOf(info.tag4) < 0) return;

        var endV = args[2].toInt32() >>> 0;
        var sz = endV - beginV;
        var task = safeR(beginV, sz > 0 && sz <= 512 ? sz : 112);
        results.push({
            tag4: info.tag4,
            begin: bk,
            metaPtr: '0x' + info.metaPtr.toString(16),
            magicOff: info.magicOff,
            a3: '0x' + (args[3].toInt32() >>> 0).toString(16),
            task: task,
            meta: info.meta,
            deep: deepPtrs(info.meta)
        });
        send({t:'hit', tag4: info.tag4, begin: bk, n: results.length});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go'}); });
recv('dump', function(_) { send({t:'dump', results: results}); });
send({t:'ready'});
""" % json.dumps(list(TARGET_TAGS))

results = []
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
        print('[+] Phase2')
    elif p.get('t') == 'hit':
        print(f'  ★ {p["tag4"]} begin={p["begin"]} #{p["n"]}')
    elif p.get('t') == 'dump':
        results.extend(p.get('results', []))
        dump_ok[0] = True

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)
print('[Phase1] 8s...')
time.sleep(8)
sc.post({'type': 'phase2'})
print('\n>>> 90s 内请转发：FTA 图片 →「海鸟与鱼」<<<\n')
t0 = time.time()
while time.time() - t0 < 90:
    time.sleep(0.5)
sc.post({'type': 'dump'})
while not dump_ok[0]:
    time.sleep(0.2)

print(f'\n[结果] {len(results)} 个 tag4 对象')
for r in results:
    for d in r.get('deep', []):
        b = bytes(d.get('bytes') or [])
        if len(b) >= 96 and b[0:4] == bytes([0x4c, 0x43, 0x79, 0x0b]):
            p92 = struct.unpack_from('<I', b, 92)[0]
            mark = 'FTA-src' if p92 == FTA_P92 else '★NEW'
            print(f'  {r["tag4"]} {r["begin"]} payload+92={p92} [{mark}]')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'tag4_deep_{ts}.json'
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] {out}')
sc.unload()
sess.detach()
os._exit(0)
