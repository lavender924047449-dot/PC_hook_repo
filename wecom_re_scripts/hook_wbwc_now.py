# hook_wbwc_now.py — 仅捕获 tag4=WbWC，60s 窗口
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
        var m = new Uint8Array(ptr(metaPtr).readByteArray(256));
        for (var i = 0; i < m.length - 3; i++) {
            if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                if (i + 28 <= m.length) {
                    return {
                        tag4: String.fromCharCode(m[i+24], m[i+25], m[i+26], m[i+27]),
                        metaPtr: metaPtr,
                        meta: safeR(metaPtr, 1024)
                    };
                }
            }
        }
    } catch(e) {}
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
        var endV = args[2].toInt32() >>> 0;
        var sz = endV - beginV;
        var task = safeR(beginV, sz > 0 && sz <= 512 ? sz : 112);
        var ptrs = [];
        if (task) {
            for (var off = 0; off < Math.min(task.length, 112); off += 4) {
                var pv = (task[off])|(task[off+1]<<8)|(task[off+2]<<16)|(task[off+3]<<24);
                pv = pv >>> 0;
                if (pv > 0x10000000 && pv < 0x7F000000) {
                    var inner = safeR(pv, 512);
                    if (inner) ptrs.push({off: off, ptr: '0x'+pv.toString(16), bytes: inner});
                }
            }
        }
        var rec = {begin: bk, metaPtr: '0x'+info.metaPtr.toString(16), task: task, meta: info.meta, ptrs: ptrs};
        hits.push(rec);
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
        print('[+] 监听 WbWC，60s...')
    elif p.get('t') == 'hit':
        print(f'  ★ WbWC #{p["n"]} begin={p["begin"]}')
    elif p.get('t') == 'dump':
        hits.extend(p.get('hits', []))
        dump_ok[0] = True

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(60)
sc.post({'type': 'dump'})
t0 = time.time()
while not dump_ok[0] and time.time() - t0 < 5:
    time.sleep(0.2)

print(f'\n[结果] WbWC 捕获 {len(hits)} 个')
for h in hits:
    print(f'  begin={h["begin"]} meta={h["metaPtr"]} ptrs={len(h.get("ptrs",[]))}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'wbwc_now_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] Saved: {out}')
sc.unload()
sess.detach()
os._exit(0)
