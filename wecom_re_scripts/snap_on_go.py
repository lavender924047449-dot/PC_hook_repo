# snap_on_go.py
# 精准捕获：
# T=0-8s 建立背景 baseline
# T=8s 打印 "GO" - 用户立即转发
# T=8-20s 捕获并对比
# 找出只在转发时出现的 compact/a3

import frida, subprocess, sys, os, time, threading, json, struct
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID={pid}')

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
send({t:'info', base: wxBase.toString()});

function safeR(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

var log = [];
var t0 = Date.now();

var CGI_ITER = wxBase.add(0x390B39);
Interceptor.attach(CGI_ITER, {
    onEnter: function(args){
        try{
            var ts = Date.now() - t0;
            // compact
            var compact = 'err';
            try{
                var b = new Uint8Array(args[1].readByteArray(4));
                compact = ('0'+b[0].toString(16)).slice(-2)+('0'+b[1].toString(16)).slice(-2)
                        + ('0'+b[2].toString(16)).slice(-2)+('0'+b[3].toString(16)).slice(-2);
            }catch(e){}
            // a3 vtable（读 a3[0:4]）
            var a3v = 0, a3vt = 'none';
            try{ a3v = args[3].toInt32()>>>0; if(a3v>0x10000){ var vt=new Uint8Array(args[3].readByteArray(4)); a3vt=('0'+vt[0].toString(16)).slice(-2)+('0'+vt[1].toString(16)).slice(-2)+('0'+vt[2].toString(16)).slice(-2)+('0'+vt[3].toString(16)).slice(-2); } }catch(e){}
            // a3[24:28] (secondary vtable/fptr)
            var a3_24 = 'none';
            try{ if(a3v>0x10000){ var x=new Uint8Array(ptr(a3v+24).readByteArray(4)); a3_24=('0'+x[0].toString(16)).slice(-2)+('0'+x[1].toString(16)).slice(-2)+('0'+x[2].toString(16)).slice(-2)+('0'+x[3].toString(16)).slice(-2); } }catch(e){}

            var e = {ts:ts, compact:compact, a3:'0x'+a3v.toString(16), a3vt:a3vt, a3_24:a3_24};
            // 读 256B 详细数据
            try{ e.a1b = safeR(args[1], 256); }catch(x){}
            try{ if(a3v>0x10000) e.a3b = safeR(a3v, 256); }catch(x){}
            log.push(e);
            send({t:'e', ts:ts, compact:compact, a3:'0x'+a3v.toString(16), a3_24:a3_24});
        }catch(e){}
    }
});

function safeR(p, n){ try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }catch(e){ return null; } }

recv('dump', function(_){ send({t:'dump', log:log}); });
send({t:'ready'});
"""

log = []
dump_event = threading.Event()

# 背景集合（T=0-8s）
baseline_keys = set()  # (compact, a3_24)
post_keys = set()       # (compact, a3_24) after GO

phase = 'baseline'
go_time = None

def on_message(msg, data):
    global phase
    if msg.get('type') == 'error': return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'ready': print('[+] READY - 建立背景基线中...')
    elif t == 'e':
        ts = p['ts']
        compact = p['compact']
        a3 = p['a3']
        a3_24 = p['a3_24']
        key = (compact, a3_24)
        
        if phase == 'baseline':
            baseline_keys.add(key)
        elif phase == 'post':
            if key not in baseline_keys:
                post_keys.add(key)
                print(f'  ★★★ 新 key! ts={ts}ms compact={compact} a3={a3} a3_24={a3_24}')
    elif t == 'dump':
        log.extend(p.get('log', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print('[*] 建立背景基线 8s...')
time.sleep(8)

phase = 'post'
go_time = time.time()
print()
print('='*60)
print('★★★★★ GO! 请立即在企微转发消息！★★★★★')
print('='*60)
print()

time.sleep(20)
print('\n[*] 结束，dump...')
sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

# ─── 分析 ─────────────────────────────────────────────────────────────────────
print(f'\n[总记录: {len(log)}]')

# 找 GO 之后出现的新 compact/a3_24 组合
go_ts = 10000  # 约 T=10000ms
new_entries = [e for e in log if e['ts'] > go_ts and (e['compact'], e['a3_24']) not in baseline_keys]

print(f'\n[GO 后新出现的 CGI 调用 ({len(new_entries)} 条)]:')

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80): return v, pos
    return None, pos

def parse_proto(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 40:
        if bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag & 7; fn = tag >> 3
            if fn == 0 or fn > 5000: break
            if w == 0:
                v, i = decode_varint(bs, i); fields.append((fn, 'v', v))
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 200000 or i2+ln > len(bs): break
                pay = bs[i2:i2+ln]; i = i2+ln
                try: fields.append((fn, 's', pay.decode('utf-8')))
                except: fields.append((fn, 'b', pay))
            elif w == 5:
                if i+4<=len(bs):
                    v=struct.unpack_from('<I',bs,i)[0]; i+=4; fields.append((fn,'i32',v))
                else: break
            elif w == 1:
                if i+8<=len(bs):
                    v=struct.unpack_from('<Q',bs,i)[0]; i+=8; fields.append((fn,'i64',v))
                else: break
            else: break
        except: break
    return fields

seen_new = {}
for e in new_entries:
    key = (e['compact'], e['a3_24'])
    if key in seen_new: continue
    seen_new[key] = e
    print(f'\n  ts={e["ts"]}ms compact={e["compact"]} a3={e["a3"]} a3_24={e["a3_24"]}')
    
    if e.get('a1b'):
        bs = bytes(e['a1b'])
        h = ' '.join(f'{b:02x}' for b in bs[:32])
        print(f'    a1[0:32]: {h}')
        pf = parse_proto(bs[4:])
        if pf:
            print('    a1 proto(skip 4B):')
            for fn, wt, v in pf[:10]:
                if wt == 'v': print(f'      f{fn}={v}(0x{v:x})')
                elif wt == 's': print(f'      f{fn}={repr(v[:60])}')
                elif wt == 'b': print(f'      f{fn}=bytes[{len(v)}]:{v[:8].hex()}')

    if e.get('a3b'):
        bs = bytes(e['a3b'])
        h = ' '.join(f'{b:02x}' for b in bs[:48])
        print(f'    a3[0:48]: {h}')
        pf = parse_proto(bs)
        if pf:
            print('    a3 proto:')
            for fn, wt, v in pf[:10]:
                if wt == 'v': print(f'      f{fn}={v}(0x{v:x})')
                elif wt == 's': print(f'      f{fn}={repr(v[:60])}')
                elif wt == 'b': print(f'      f{fn}=bytes[{len(v)}]:{v[:8].hex()}')

if not new_entries:
    print('  (无新调用 → 转发在 GO 之前或未通过 CGI_ITER)')
    print('\n  [背景 compact 统计]:')
    cnt = defaultdict(int)
    for e in log: cnt[(e['compact'], e['a3_24'])] += 1
    for k, v in sorted(cnt.items(), key=lambda x: -x[1])[:10]:
        print(f'    compact={k[0]} a3_24={k[1]}: {v}次')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'snap_on_go_{ts}.json'
out.write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
