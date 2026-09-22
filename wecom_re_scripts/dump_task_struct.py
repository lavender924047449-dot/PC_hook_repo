# dump_task_struct.py
# Hook RVA 0x390CE0，用户转发 1 次后 dump 新 task 对象完整结构
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
    raise RuntimeError('WXWork main process not found (:9882)')

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
var wxBase = wx.base;
send({t:'base', v:wxBase.toString()});

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

var startTs = Date.now();
var baseline = {};
var phase = 1;
var captures = [];

Interceptor.attach(wxBase.add(0x390ce0), {
    onEnter: function(args) {
        var elapsed = Date.now() - startTs;
        var a0 = args[0].toInt32() >>> 0;
        var beginV = args[1].toInt32() >>> 0;
        var endV = args[2].toInt32() >>> 0;
        var a3 = args[3].toInt32() >>> 0;
        var sz = endV - beginV;
        if (sz <= 0 || sz > 512) return;

        var bk = '0x' + beginV.toString(16);
        if (phase === 1) {
            baseline[bk] = true;
            return;
        }

        // Phase 2: 每个新地址只 capture 一次
        if (baseline[bk]) return;
        if (captures.some(function(c) { return c.begin === bk; })) return;

        var data = safeR(beginV, sz);
        var ptrs = [];
        if (data) {
            for (var i = 0; i < Math.min(sz, 112); i += 4) {
                var pv = (data[i]) | (data[i+1]<<8) | (data[i+2]<<16) | (data[i+3]<<24);
                pv = pv >>> 0;
                if (pv > 0x10000000 && pv < 0x7F000000) {
                    var inner = safeR(pv, 512);
                    if (inner) ptrs.push({off: i, ptr: '0x'+pv.toString(16), bytes: inner});
                }
            }
        }

        var cap = {
            elapsed: elapsed,
            a0: '0x' + a0.toString(16),
            begin: bk,
            end: '0x' + endV.toString(16),
            sz: sz,
            a3: '0x' + a3.toString(16),
            data: data,
            ptrs: ptrs
        };
        captures.push(cap);
        send({t:'new', begin: bk, sz: sz, elapsed: elapsed, n: captures.length});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go'}); });
recv('dump', function(_) { send({t:'dump', caps: captures, baseline: Object.keys(baseline)}); });
send({t:'ready'});
"""

captures = []
dump_done = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description", "")[:200]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'base':
        print(f'  wxBase={p["v"]}')
    elif t == 'ready':
        print('[+] Hook @ RVA 0x390CE0 ready')
    elif t == 'go':
        print('[+] Phase 2 started')
    elif t == 'new':
        el = p['elapsed'] / 1000.0
        print(f'  ★ NEW #{p["n"]} t={el:.1f}s begin={p["begin"]} sz={p["sz"]}')
    elif t == 'dump':
        captures.extend(p.get('caps', []))
        print(f'  baseline addrs: {len(p.get("baseline", []))}')
        dump_done[0] = True

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1.5)

print('\n[Phase 1] 8s baseline...')
time.sleep(8)

sc.post({'type': 'phase2'})
time.sleep(0.3)

print('\n' + '=' * 60)
print('>>> 请立即在企微转发 1 条消息（图片/文字均可）<<<')
print('=' * 60)

# 等待最多 60s，或捕获到 >=3 个新地址
t0 = time.time()
while time.time() - t0 < 60 and len(captures) < 3:
    time.sleep(0.5)

time.sleep(2)
sc.post({'type': 'dump'})
t1 = time.time()
while not dump_done[0] and time.time() - t1 < 5:
    time.sleep(0.2)

# ── 分析 ──────────────────────────────────────────────────
def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80):
            return v, pos
    return None, pos

def parse_proto(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 40:
        if bs[i] == 0:
            break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None:
                break
            w = tag & 7; fn = tag >> 3
            if fn == 0 or fn > 2000:
                break
            if w == 0:
                v, i = decode_varint(bs, i)
                if v is None:
                    break
                fields.append((fn, 'v', v))
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 100000 or i2 + ln > len(bs):
                    break
                pay = bs[i2:i2 + ln]; i = i2 + ln
                try:
                    fields.append((fn, 's', pay.decode('utf-8')))
                except Exception:
                    fields.append((fn, 'b', pay.hex()))
            elif w == 5:
                if i + 4 <= len(bs):
                    v = struct.unpack_from('<I', bs, i)[0]; i += 4
                    fields.append((fn, 'i32', v))
                else:
                    break
            elif w == 1:
                if i + 8 <= len(bs):
                    v = struct.unpack_from('<Q', bs, i)[0]; i += 8
                    fields.append((fn, 'i64', v))
                else:
                    break
            else:
                break
        except Exception:
            break
    return fields

print(f'\n[结果] 捕获 {len(captures)} 个新 task 对象')

for cap in captures:
    begin = cap['begin']
    raw = bytes(cap.get('data') or [])
    print(f'\n{"=" * 65}')
    print(f'begin={begin} sz={cap["sz"]} t={cap["elapsed"]/1000:.1f}s')
    print(f'a0={cap["a0"]} a3={cap["a3"]}')
    print(f'hex: {raw.hex()}')

    print('  ptr slots:')
    for i in range(0, min(len(raw), 112), 4):
        pv = struct.unpack_from('<I', raw, i)[0]
        tag = ' ← ptr' if 0x10000000 < pv < 0x7F000000 else ''
        print(f'    [{i:3d}] 0x{pv:08x}{tag}')

    pf = parse_proto(raw)
    if pf:
        print('  proto (direct):')
        for fn, wt, v in pf:
            if wt == 'v':
                print(f'    f{fn}={v} (0x{v:x})')
            elif wt == 's':
                print(f'    f{fn}={repr(v[:80])}')
            else:
                print(f'    f{fn}={wt}:{v}')

    for ip in cap.get('ptrs', []):
        bs2 = bytes(ip['bytes'])
        print(f'\n  inner[off={ip["off"]}] -> {ip["ptr"]}')
        print(f'    hex[0:128]: {bs2[:128].hex()}')
        pf2 = parse_proto(bs2)
        if pf2:
            print('    proto:')
            for fn, wt, v in pf2[:20]:
                if wt == 'v':
                    print(f'      f{fn}={v} (0x{v:x})')
                elif wt == 's':
                    print(f'      f{fn}={repr(v[:80])}')
                elif wt == 'b':
                    print(f'      f{fn}=bytes:{v[:64]}')

# 高亮目标地址
target = '0x19f9fb00'
found = [c for c in captures if c['begin'].lower() == target]
if found:
    print(f'\n★★★ 目标地址 {target} 已捕获 ★★★')
else:
    print(f'\n⚠ 目标地址 {target} 未出现，但捕获了 {len(captures)} 个其他新地址')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'dump_task_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
