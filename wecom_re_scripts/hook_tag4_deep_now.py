# hook_tag4_deep_now.py — 即时捕获 i+Ax / b0jW / WbWC 深度 dump
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
var t0 = Date.now();

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

var seen = {};
var results = [];

Interceptor.attach(wx.base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var bk = '0x' + beginV.toString(16);
        var info = readTag4(beginV);
        if (!info || TARGET.indexOf(info.tag4) < 0) return;

        var key = info.tag4 + '|' + bk;
        var elapsed = Date.now() - t0;
        var endV = args[2].toInt32() >>> 0;
        var sz = endV - beginV;
        var task = safeR(beginV, sz > 0 && sz <= 512 ? sz : 112);

        if (!seen[key]) {
            seen[key] = true;
            results.push({
                elapsed_ms: elapsed,
                tag4: info.tag4,
                begin: bk,
                metaPtr: '0x' + info.metaPtr.toString(16),
                magicOff: info.magicOff,
                a3: '0x' + (args[3].toInt32() >>> 0).toString(16),
                task: task,
                meta: info.meta,
                deep: deepPtrs(info.meta)
            });
            send({t:'new', tag4: info.tag4, begin: bk, elapsed: elapsed, n: results.length});
        } else {
            send({t:'repeat', tag4: info.tag4, begin: bk, elapsed: elapsed});
        }
    }
});

recv('dump', function(_) { send({t:'dump', results: results}); });
send({t:'ready'});
""" % json.dumps(list(TARGET_TAGS))

results = []
dump_ok = [False]
first_hit = [None]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:250]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print('[+] 即时监听 i+Ax/b0jW/WbWC，60s...')
    elif p.get('t') == 'new':
        el = p['elapsed'] / 1000.0
        print(f'  ★ NEW #{p["n"]} {p["tag4"]} begin={p["begin"]} t={el:.1f}s')
        if first_hit[0] is None:
            first_hit[0] = p['elapsed']
    elif p.get('t') == 'repeat':
        pass
    elif p.get('t') == 'dump':
        results.extend(p.get('results', []))
        dump_ok[0] = True

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

print(f'\n[结果] 唯一 tag4 对象: {len(results)}')

def scan_u32(bs, label):
    if not bs:
        return
    hits = []
    for off in range(0, len(bs) - 3, 4):
        v = struct.unpack_from('<I', bs, off)[0]
        if v != 0 and v != FTA_P92 and 1000 < v < 0x7FFFFFFF:
            hits.append((off, v))
    return hits

all_p92 = set()
dest_candidates = []

for r in results:
    print(f'\n--- {r["tag4"]} begin={r["begin"]} t={r["elapsed_ms"]/1000:.1f}s ---')
    meta = bytes(r.get('meta') or [])
    for off in [80, 84, 88, 92, 96, 100, 128, 140, 148, 152, 160, 172, 180]:
        if off + 4 <= len(meta):
            v = struct.unpack_from('<I', meta, off)[0]
            print(f'  meta+{off:3d} = {v} (0x{v:08x})')

    for d in r.get('deep', []):
        b = bytes(d.get('bytes') or [])
        if len(b) >= 96 and b[0:4] == bytes([0x4C, 0x43, 0x79, 0x0B]):
            p92 = struct.unpack_from('<I', b, 92)[0]
            all_p92.add(p92)
            tag = 'FTA-src' if p92 == FTA_P92 else '★DEST?'
            print(f'  payload@{d["ptr"]} +92={p92} [{tag}]')
            for off in [84, 88, 92, 96, 100, 148, 152, 172, 180]:
                if off + 4 <= len(b):
                    v = struct.unpack_from('<I', b, off)[0]
                    if v != FTA_P92:
                        dest_candidates.append((r['tag4'], r['begin'], off, v))

# 汇总非 FTA 的 u32
print('\n[非 FTA_P92 的 payload/meta u32 候选]')
seen_v = set()
for item in dest_candidates:
    tag4, begin, off, v = item
    if v in seen_v:
        continue
    seen_v.add(v)
    print(f'  {tag4} {begin} +{off} = {v} (0x{v:08x})')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'tag4_deep_{ts}.json'
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
