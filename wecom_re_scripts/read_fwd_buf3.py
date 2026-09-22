# read_fwd_buf3.py — 同 read_fwd_buf2 但 JS 发送完整 data 字节
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
var wxBase = wx.base;

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

var startTs = Date.now();
var BASELINE = {};
var phase = 1;

Interceptor.attach(wxBase.add(0x390ce0), {
    onEnter: function(args) {
        var elapsed = Date.now() - startTs;
        var beginV = args[1].toInt32() >>> 0;
        var endV   = args[2].toInt32() >>> 0;
        var sz = endV - beginV;
        if (sz <= 0 || sz > 512) return;

        var bk = '0x'+beginV.toString(16);

        if (phase === 1) {
            // 只记录基线地址
            BASELINE[bk] = true;
            return;
        }

        // Phase 2: 只处理新地址
        if (BASELINE[bk]) return;

        // 读完整数据
        var data = safeR(beginV, sz);
        // 读内层指针 (每4字节读作指针，取第一个有效的，读其内容)
        var innerPtrs = [];
        if (data) {
            for (var i = 0; i < Math.min(sz, 48); i += 4) {
                var pv = (data[i]) | (data[i+1]<<8) | (data[i+2]<<16) | (data[i+3]<<24);
                pv = pv >>> 0;
                if (pv > 0x10000000 && pv < 0x7F000000) {
                    var inner = safeR(pv, 256);
                    if (inner) innerPtrs.push({off:i, ptr:'0x'+pv.toString(16), bytes:inner});
                    if (innerPtrs.length >= 4) break;
                }
            }
        }

        send({t:'hit', elapsed:elapsed, begin:bk, sz:sz, data:data, innerPtrs:innerPtrs});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'ack'}); });
send({t:'ready'});
"""

hits = []
ack_event = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'ready': print('[+] Hook ready!')
    elif t == 'ack': ack_event[0] = True
    elif t == 'hit':
        hits.append(p)
        el = p['elapsed']/1000.0
        h8 = bytes(p['data'][:8]).hex() if p.get('data') else '??'
        print(f'  ★ NEW t={el:5.1f}s begin={p["begin"]} sz={p["sz"]} h8={h8}')

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1.5)

print('\n[Phase 1] 8s baseline 记录中（静默）...')
time.sleep(8)

sc.post({'type': 'phase2'})
t0 = time.time()
while not ack_event[0] and time.time()-t0 < 3:
    time.sleep(0.1)

print('\n' + '='*65)
print('★★★ 请立即在企微转发消息！（20s 窗口）★★★')
print('='*65)
time.sleep(20)

# ── 分析 ──────────────────────────────────────────────────────────────
def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b&0x7F)<<sh; sh += 7
        if not(b&0x80): return v, pos
    return None, pos

def parse_proto(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 40:
        if bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag&7; fn = tag>>3
            if fn==0 or fn>2000: break
            if w==0:
                v,i = decode_varint(bs,i)
                if v is None: break
                fields.append((fn,'v',v))
            elif w==2:
                ln,i2 = decode_varint(bs,i)
                if ln is None or ln>100000 or i2+ln>len(bs): break
                pay=bs[i2:i2+ln]; i=i2+ln
                try: fields.append((fn,'s',pay.decode('utf-8')))
                except: fields.append((fn,'b',pay[:32].hex()))
            elif w==5:
                if i+4<=len(bs): v=struct.unpack_from('<I',bs,i)[0]; i+=4; fields.append((fn,'i32',v))
                else: break
            elif w==1:
                if i+8<=len(bs): v=struct.unpack_from('<Q',bs,i)[0]; i+=8; fields.append((fn,'i64',v))
                else: break
            else: break
        except: break
    return fields

print(f'\n[结果] 20s 内新地址命中 {len(hits)} 次')
seen = set()
for hit in hits:
    begin = hit['begin']
    raw = bytes(hit.get('data') or [])
    key = begin
    if key in seen: continue
    seen.add(key)

    print(f'\n{"="*65}')
    print(f'begin={begin} sz={hit["sz"]} t={hit["elapsed"]/1000:.1f}s')
    print(f'  hex: {raw.hex()}')
    # 指针分析
    print(f'  ptrs:')
    for i in range(0, min(len(raw),48), 4):
        pv = struct.unpack_from('<I', raw, i)[0]
        tag = ' ← ptr' if 0x10000000 < pv < 0x7F000000 else ''
        print(f'    [{i:3d}] 0x{pv:08x}{tag}')
    # proto 解析
    pf = parse_proto(raw)
    if pf:
        print(f'  proto (direct):')
        for fn,wt,v in pf:
            if wt=='v': print(f'    f{fn}={v} (0x{v:x})')
            elif wt=='s': print(f'    f{fn}={repr(v[:60])}')
            elif wt in ('b','i32','i64'): print(f'    f{fn}={wt}:{v}')

    # 内层指针数据
    for ip in hit.get('innerPtrs', []):
        bs2 = bytes(ip['bytes'])
        pf2 = parse_proto(bs2)
        print(f'\n  inner[off={ip["off"]}] -> {ip["ptr"]}')
        print(f'    hex: {bs2[:64].hex()}')
        if pf2:
            print(f'    proto:')
            for fn,wt,v in pf2[:15]:
                if wt=='v': print(f'      f{fn}={v} (0x{v:x})')
                elif wt=='s': print(f'      f{fn}={repr(v[:60])}')
                elif wt=='b': print(f'      f{fn}=bytes:{v[:32]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'fwd_buf3_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')
sc.unload()
sess.detach()
os._exit(0)
