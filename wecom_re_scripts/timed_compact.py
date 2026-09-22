# timed_compact.py
# 记录 60 秒内所有 CGI_ITER 调用的 compact + 时间戳
# 用户在特定时间点转发，后续按时间对比找转发 compact

import frida, subprocess, sys, os, time, threading, json, struct
from pathlib import Path
from datetime import datetime

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

function safeReadBytes(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

var log = [];  // {ts, compact, a3_ptr, a3_bytes}
var t0 = Date.now();

var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var ts = Date.now() - t0;
                var compact = '';
                try{
                    var b = new Uint8Array(args[1].readByteArray(4));
                    compact = ('0'+b[0].toString(16)).slice(-2)
                            + ('0'+b[1].toString(16)).slice(-2)
                            + ('0'+b[2].toString(16)).slice(-2)
                            + ('0'+b[3].toString(16)).slice(-2);
                }catch(e){ compact = '????????'; }

                var a3v = 0;
                try{ a3v = args[3].toInt32() >>> 0; }catch(e){}

                // 记录每次调用（不去重，保留时间信息）
                var entry = {ts:ts, compact:compact, a3:'0x'+a3v.toString(16)};

                // 若 compact 不是常见背景 compact 或 a3 非零，读 a3 详细数据
                var isCommon = (compact==='01000000' || compact==='01650000' || compact==='0184f125');
                if(!isCommon || a3v > 0x10000){
                    entry.a3_bytes = safeReadBytes(a3v, 256);
                    // 读 args[1] 后 compact 后的数据（proto payload）
                    entry.a1_bytes = safeReadBytes(args[1], 256);
                }

                log.push(entry);
                send({t:'cgi', ts:ts, compact:compact, a3:'0x'+a3v.toString(16), isCommon:isCommon});
            }catch(e){}
        }
    });
    send({t:'ok', fn:'CGI_ITER'});
} catch(e){ send({t:'fail', fn:'CGI_ITER', m:e.message}); }

recv('dump', function(_){ send({t:'dump', log:log}); });
send({t:'ready'});
"""

log_entries = []
dump_event = threading.Event()
last_print_compact = {}

def on_message(msg, data):
    if msg.get('type') == 'error': return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'ready':
        print('[+] HOOKS READY!')
    elif t == 'cgi':
        compact = p['compact']
        ts = p['ts']
        a3 = p['a3']
        is_common = p.get('isCommon', True)
        # 只打印非常见 compact，或 a3!=0
        if not is_common or a3 not in ('0x0',):
            marker = ''
            if a3 != '0x0': marker = f'  [a3={a3}]'
            print(f'  [{ts:5d}ms] compact={compact}{marker}')
        else:
            # 常见 compact 只每 5s 打印一次
            last = last_print_compact.get(compact, -5001)
            if ts - last > 5000:
                last_print_compact[compact] = ts
                print(f'  [{ts:5d}ms] {compact} (背景)')
    elif t == 'dump':
        log_entries.extend(p.get('log', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print()
print('='*60)
print('记录所有 compact 60 秒...')
print()
print('[步骤] T=0s  开始')
print('[步骤] T=10s 请转发第一次')
print('[步骤] T=25s 请转发第二次')
print('[步骤] T=40s 结束，等待分析')
print('='*60)

t_start = time.time()

# 倒计时提示
for milestone in [10, 25, 40]:
    remaining = milestone - (time.time() - t_start)
    if remaining > 0:
        time.sleep(max(0, remaining - (time.time() - t_start)))
    elapsed = time.time() - t_start
    if milestone == 10:
        print(f'\n>>> T={elapsed:.1f}s: ★★★ 请立即转发！★★★\n')
    elif milestone == 25:
        print(f'\n>>> T={elapsed:.1f}s: ★★★ 请再转发一次！★★★\n')
    elif milestone == 40:
        print(f'\n>>> T={elapsed:.1f}s: 收集完毕，分析中...')

sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

# ─── 分析：找转发相关 compact ──────────────────────────────────────────────────

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80): return v, pos
    return None, pos

def parse_proto_all(bs):
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
                if ln is None or ln > 500000 or i2 + ln > len(bs): break
                pay = bs[i2:i2+ln]; i = i2 + ln
                try: fields.append((fn, 's', pay.decode('utf-8')))
                except: fields.append((fn, 'b', pay))
            elif w == 5:
                if i+4 <= len(bs):
                    v = struct.unpack_from('<I', bs, i)[0]; i += 4
                    fields.append((fn, 'i32', v))
                else: break
            elif w == 1:
                if i+8 <= len(bs):
                    v = struct.unpack_from('<Q', bs, i)[0]; i += 8
                    fields.append((fn, 'i64', v))
                else: break
            else: break
        except: break
    return fields

print(f'\n共捕获 {len(log_entries)} 条记录')

# 统计 compact 出现次数 + 时间分布
from collections import defaultdict
compact_times = defaultdict(list)
for e in log_entries:
    compact_times[e['compact']].append(e['ts'])

print('\n[Compact 统计]:')
for c, times in sorted(compact_times.items(), key=lambda x: len(x[1]), reverse=True):
    print(f'  {c}: {len(times)}次  时间段 {min(times)}-{max(times)}ms')

# 找在 T=10s 和 T=25s 附近出现的 compact（±3s）
fwd_windows = [(8000, 13000), (23000, 28000)]
print('\n[转发时间窗内的 compact]:')
for ws, we in fwd_windows:
    window_compacts = defaultdict(int)
    for e in log_entries:
        if ws <= e['ts'] <= we:
            window_compacts[e['compact']] += 1
    print(f'  T={ws//1000}-{we//1000}s: {dict(window_compacts)}')

# 打印有 a1_bytes/a3_bytes 的条目
print('\n[有详细数据的条目（非常见 compact 或 a3≠0）]:')
for e in log_entries:
    if e.get('a1_bytes') or e.get('a3_bytes'):
        print(f'\n  T={e["ts"]}ms compact={e["compact"]} a3={e["a3"]}')
        if e.get('a1_bytes'):
            bs = bytes(e['a1_bytes'])
            h = ' '.join(f'{b:02x}' for b in bs[:32])
            print(f'    a1[0:32]: {h}')
            pf = parse_proto_all(bs[4:])  # skip compact
            if pf:
                print(f'    proto(skip 4B):')
                for fn, wt, v in pf[:10]:
                    if wt == 'v': print(f'      f{fn}={v} (0x{v:x})')
                    elif wt == 's': print(f'      f{fn}={repr(v[:50])}')
                    elif wt == 'b': print(f'      f{fn}=bytes[{len(v)}]:{v[:8].hex()}')
        if e.get('a3_bytes'):
            bs = bytes(e['a3_bytes'])
            h = ' '.join(f'{b:02x}' for b in bs[:32])
            print(f'    a3[0:32]: {h}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'timed_compact_{ts}.json'
out.write_text(json.dumps({'log': log_entries, 'compact_times': {k: v for k,v in compact_times.items()}}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
