# hook_tag4_caller.py — hook 0x390CE0，当 metadata tag4 为新值时抓 caller 链
import frida, subprocess, sys, os, time, json
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
var size = wx.size;

function readTag4(metaPtr) {
    try {
        var m = new Uint8Array(ptr(metaPtr).readByteArray(128));
        for (var i = 0; i < m.length - 3; i++) {
            if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                if (i + 28 <= m.length) {
                    return String.fromCharCode(m[i+24], m[i+25], m[i+26], m[i+27]);
                }
            }
        }
    } catch(e) {}
    return '';
}

function ebpChain(maxN) {
    var out = [];
    try {
        var fp = this.context.ebp;
        for (var i = 0; i < maxN; i++) {
            if (!fp || fp.isNull()) break;
            var ret = fp.add(4).readPointer();
            var rva = ret.sub(base).toInt32() >>> 0;
            if (rva > 0 && rva < size) out.push('0x' + rva.toString(16));
            fp = fp.readPointer();
        }
    } catch(e) {}
    return out;
}

var baseline = {};
var phase = 1;
var hits = [];

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var endV = args[2].toInt32() >>> 0;
        var sz = endV - beginV;
        if (sz <= 0 || sz > 512) return;

        var metaPtr = 0;
        try { metaPtr = ptr(beginV).add(52).readU32() >>> 0; } catch(e) { return; }
        var tag4 = readTag4(metaPtr);
        if (!tag4 || tag4.indexOf('\x00') >= 0) return;

        var bk = '0x' + beginV.toString(16);
        if (phase === 1) {
            baseline[tag4 + '|' + bk] = true;
            return;
        }

        var key = tag4 + '|' + bk;
        if (baseline[key]) return;

        var chain = ebpChain.call(this, 12);
        var rec = {
            tag4: tag4,
            begin: bk,
            metaPtr: '0x' + metaPtr.toString(16),
            chain: chain,
            a3: '0x' + (args[3].toInt32() >>> 0).toString(16)
        };
        hits.push(rec);
        send({t:'hit', tag4:tag4, begin:bk, chain:chain.slice(0,8)});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go'}); });
recv('dump', function(_) { send({t:'dump', hits:hits, baseline:Object.keys(baseline)}); });
send({t:'ready', base:base.toString()});
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
    t = p.get('t', '')
    if t == 'ready':
        print(f'  base={p["base"]}')
        print('[+] Hook 0x390CE0 + EBP caller chain ready')
    elif t == 'go':
        print('[+] Phase 2')
    elif t == 'hit':
        print(f'  ★ tag4={p["tag4"]!r} begin={p["begin"]}')
        print(f'    chain: {" -> ".join(p["chain"])}')
    elif t == 'dump':
        hits.extend(p.get('hits', []))
        print(f'  baseline keys: {len(p.get("baseline", []))}')
        dump_ok[0] = True

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1.5)

print('\n[Phase 1] 8s baseline...')
time.sleep(8)
sc.post({'type': 'phase2'})
time.sleep(0.2)

print('\n' + '=' * 60)
print('>>> 请立即在企微转发 1 条消息 <<<')
print('=' * 60)

t0 = time.time()
while time.time() - t0 < 45 and len(hits) < 8:
    time.sleep(0.5)
time.sleep(1)

sc.post({'type': 'dump'})
t1 = time.time()
while not dump_ok[0] and time.time() - t1 < 5:
    time.sleep(0.2)

print(f'\n[结果] {len(hits)} 个新 tag4 事件')
for h in hits:
    print(f'\n  tag4={h["tag4"]!r} begin={h["begin"]} meta={h["metaPtr"]}')
    print(f'  caller chain (RVA):')
    for i, rva in enumerate(h.get('chain', [])):
        print(f'    [{i}] {rva}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'tag4_caller_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
