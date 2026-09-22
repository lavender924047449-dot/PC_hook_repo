# read_fwd_buf2.py
# 对 RVA 0x390ce0 做 phase-diff：
# Phase 1 (8s): 记录 baseline begin 地址 + 内容
# Phase 2 (20s): 转发期间，找新出现的 begin 地址并读全部 112 字节 + 解析 proto
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
send({t:'base', v:wxBase.toString()});

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

var startTs = Date.now();
var events = [];

// RVA 0x390ce0 — 新版本 CGI 遍历函数
Interceptor.attach(wxBase.add(0x390ce0), {
    onEnter: function(args) {
        var elapsed = Date.now() - startTs;
        var beginV = args[1].toInt32() >>> 0;
        var endV   = args[2].toInt32() >>> 0;
        var a0     = args[0].toInt32() >>> 0;
        var a3     = args[3].toInt32() >>> 0;
        var sz = endV - beginV;

        // 读 begin 处全部字节
        var data = null;
        if (beginV > 0x1000000 && sz > 0 && sz <= 1024) {
            data = safeR(beginV, sz);
        }
        // 额外读：begin 处作为指针，再深一层
        var inner = null;
        try {
            var p = ptr(beginV).readU32() >>> 0;
            if (p > 0x1000000 && p < 0x7f000000) {
                inner = safeR(p, 256);
            }
        } catch(e) {}

        events.push({elapsed:elapsed, a0:'0x'+a0.toString(16), begin:'0x'+beginV.toString(16),
                     end:'0x'+endV.toString(16), sz:sz, data:data, inner:inner});

        // 实时上报非零 data 的前 8 字节
        if (data && data.some(b => b !== 0)) {
            var h8 = data.slice(0,8).map(b=>('0'+b.toString(16)).slice(-2)).join('');
            send({t:'hit', elapsed:elapsed, begin:'0x'+beginV.toString(16), sz:sz, h8:h8});
        }
    }
});
send({t:'ready'});
"""

all_events = []
start_ts = None

def on_msg(msg, data):
    global start_ts
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'base': print(f'  wxBase={p["v"]}')
    elif t == 'ready':
        start_ts = time.time()
        print('[+] Hook ready!')
    elif t == 'hit':
        all_events.append(p)
        el = p['elapsed']/1000.0
        print(f'  t={el:6.1f}s begin={p["begin"]} sz={p["sz"]} h8={p["h8"]}')

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()

t0 = time.time()
while start_ts is None and time.time()-t0 < 10:
    time.sleep(0.2)

print('\n[Phase 1] 8s baseline...')
time.sleep(8)

# 记录 baseline begin 地址和 h8 模式
baseline = {}
for e in all_events:
    k = (e.get('begin',''), e.get('sz',0), e.get('h8',''))
    baseline[k] = baseline.get(k, 0) + 1

print(f'  Baseline patterns ({len(baseline)}):')
for k, cnt in sorted(baseline.items(), key=lambda x:-x[1]):
    print(f'    begin={k[0]} sz={k[1]} h8={k[2]} x{cnt}')

p1_count = len(all_events)
all_events.clear()

print('\n' + '='*60)
print('*** 请立即在企微转发消息！（20s 窗口）***')
print('='*60)
time.sleep(20)

# 分析新出现的模式
fwd_events = list(all_events)
print(f'\n[Phase 2] 20s 内 {len(fwd_events)} 次命中')

new_patterns = {}
for e in fwd_events:
    k = (e.get('begin',''), e.get('sz',0), e.get('h8',''))
    if k not in baseline:
        new_patterns[k] = new_patterns.get(k, 0) + 1

print(f'\n★ 新出现 pattern ({len(new_patterns)}个):')
for k, cnt in sorted(new_patterns.items(), key=lambda x:-x[1]):
    print(f'  begin={k[0]} sz={k[1]} h8={k[2]} x{cnt}')

# 尝试用 proto 解析 Phase 2 中所有非空数据
def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b&0x7F)<<sh; sh += 7
        if not(b&0x80): return v, pos
    return None, pos

def parse_proto(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 30:
        if i < len(bs) and bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag&7; fn = tag>>3
            if fn == 0 or fn > 2000: break
            if w == 0:
                v, i = decode_varint(bs, i)
                if v is None: break
                fields.append((fn, 'v', v))
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 50000 or i2+ln > len(bs): break
                pay = bs[i2:i2+ln]; i = i2+ln
                try: fields.append((fn, 's', pay.decode('utf-8')))
                except: fields.append((fn, 'b', pay[:16].hex()))
            elif w == 5: i += 4; fields.append((fn, 'i32', 0))
            elif w == 1: i += 8; fields.append((fn, 'i64', 0))
            else: break
        except: break
    return fields

print('\n[Proto 解析 Phase2 数据]:')
seen_begins = set()
for e in fwd_events:
    begin = e.get('begin','')
    if begin in seen_begins: continue
    seen_begins.add(begin)
    raw = e.get('data') or []
    if not raw: continue
    bs = bytes(raw)
    # 跳过全零
    if all(b==0 for b in bs): continue
    pf = parse_proto(bs)
    if pf:
        print(f'  begin={begin} sz={e.get("sz")} proto:')
        for fn, wt, v in pf[:10]:
            if wt=='v': print(f'    f{fn}={v} (0x{v:x})')
            elif wt=='s': print(f'    f{fn}={repr(v[:50])}')
            elif wt=='b': print(f'    f{fn}=bytes:{v}')
    # 也解析 inner
    inner = e.get('inner')
    if inner:
        bs2 = bytes(inner)
        pf2 = parse_proto(bs2)
        if pf2:
            print(f'  inner @ begin={begin} proto:')
            for fn, wt, v in pf2[:10]:
                if wt=='v': print(f'    f{fn}={v}')
                elif wt=='s': print(f'    f{fn}={repr(v[:50])}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'fwd_buf2_{ts}.json'
out.write_text(json.dumps(fwd_events, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')
sc.unload()
sess.detach()
os._exit(0)
