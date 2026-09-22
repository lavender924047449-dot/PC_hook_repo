# hook_tag4_v2.py — 按 tag4 字符串差分（非地址），捕获 caller 链
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

function readTag4FromTask(beginV) {
    try {
        var metaPtr = ptr(beginV).add(52).readU32() >>> 0;
        var m = new Uint8Array(ptr(metaPtr).readByteArray(256));
        for (var i = 0; i < m.length - 3; i++) {
            if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                if (i + 28 <= m.length) {
                    var t = String.fromCharCode(m[i+24], m[i+25], m[i+26], m[i+27]);
                    if (/^[\x21-\x7e]{4}$/.test(t)) return {tag4:t, metaPtr:metaPtr, magicOff:i};
                }
            }
        }
    } catch(e) {}
    return null;
}

function ebpChain(ctx) {
    var out = [];
    try {
        var fp = ctx.ebp;
        for (var i = 0; i < 14; i++) {
            if (!fp || fp.isNull()) break;
            var ret = fp.add(4).readPointer();
            var rva = ret.sub(base).toInt32() >>> 0;
            if (rva > 0 && rva < size) out.push('0x' + rva.toString(16));
            fp = fp.readPointer();
        }
    } catch(e) {}
    return out;
}

var baselineTags = {};
var phase = 1;
var hits = [];

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var info = readTag4FromTask(beginV);
        if (!info) return;

        if (phase === 1) {
            baselineTags[info.tag4] = (baselineTags[info.tag4]||0) + 1;
            return;
        }

        // Phase2: 仅报告 baseline 中少见/未见的 tag4
        if (baselineTags[info.tag4] && baselineTags[info.tag4] > 50) return;

        var chain = ebpChain(this.context);
        var rec = {
            tag4: info.tag4,
            begin: '0x' + beginV.toString(16),
            metaPtr: '0x' + info.metaPtr.toString(16),
            magicOff: info.magicOff,
            chain: chain,
            a3: '0x' + (args[3].toInt32() >>> 0).toString(16)
        };
        hits.push(rec);
        send({t:'hit', tag4:info.tag4, chain:chain.slice(0,10)});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go', baseline:baselineTags}); });
recv('dump', function(_) { send({t:'dump', hits:hits, baseline:baselineTags}); });
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
    t = p.get('t', '')
    if t == 'ready':
        print('[+] Hook ready')
    elif t == 'go':
        print(f'[+] Phase2 baseline tags: {p.get("baseline", {})}')
    elif t == 'hit':
        print(f'  ★ tag4={p["tag4"]!r}')
        print(f'    chain: {" -> ".join(p["chain"])}')
    elif t == 'dump':
        hits.extend(p.get('hits', []))
        dump_ok[0] = True

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1.5)

print('\n[Phase 1] 8s — 记录 baseline tag4 频率...')
time.sleep(8)
sc.post({'type': 'phase2'})
time.sleep(0.3)

print('\n' + '=' * 60)
print('>>> 请立即在企微转发 1 条消息（60s 窗口）<<<')
print('=' * 60)

t0 = time.time()
while time.time() - t0 < 60:
    time.sleep(0.5)

sc.post({'type': 'dump'})
t1 = time.time()
while not dump_ok[0] and time.time() - t1 < 5:
    time.sleep(0.2)

print(f'\n[结果] {len(hits)} 条转发相关 tag4 事件')
for h in hits[:10]:
    print(f'  tag4={h["tag4"]!r} begin={h["begin"]}')
    print(f'    chain: {" -> ".join(h.get("chain", [])[:8])}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'tag4_caller_v2_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')

case_dir = OUT / 'work' / '20260911-184942-wxwork-native-forwardmessage-tag'
case_dir.mkdir(parents=True, exist_ok=True)
(case_dir / f'evidence_tag4_{ts}.json').write_text(
    json.dumps({'static_scan': 'scan_disk_tag4.py', 'hits': hits}, indent=2), encoding='utf-8')

print(f'\n[+] Saved: {out}')
sc.unload()
sess.detach()
os._exit(0)
