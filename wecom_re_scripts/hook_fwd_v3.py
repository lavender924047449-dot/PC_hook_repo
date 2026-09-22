# hook_fwd_v3.py
# 策略：捕获所有 args[3] != 0 的 CGI_ITER 调用（即有请求体的调用）
# 同时也捕获 compact==01004179
# 转发后自动 dump 并分析 args[3] 原始 proto

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
function safePtr(p){
    try{ return p.toInt32() >>> 0; }
    catch(e){ return 0; }
}

var captures = [];
var hitCount = 0;
var MAX_CAPS = 5;

var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var a0 = safePtr(args[0]);
                var a1 = safePtr(args[1]);
                var a2 = safePtr(args[2]);
                var a3 = safePtr(args[3]);

                // 读 compact（args[1] 的头 4 字节）
                var compact = '';
                try{
                    var b = new Uint8Array(args[1].readByteArray(4));
                    compact = ('0'+b[0].toString(16)).slice(-2)
                            + ('0'+b[1].toString(16)).slice(-2)
                            + ('0'+b[2].toString(16)).slice(-2)
                            + ('0'+b[3].toString(16)).slice(-2);
                }catch(e){ compact = '????????'; }

                // 条件1：args[3] 不为 0（有请求体）
                // 条件2：compact 已知是转发 01004179
                var isFwd = (compact === '01004179');
                var hasBody = (a3 > 0x10000);

                if(!hasBody && !isFwd) return;
                if(hitCount >= MAX_CAPS) return;
                hitCount++;

                // 读 args[1] 和 args[3] 各 512 字节
                var a1bytes = safeReadBytes(a1, 512);
                var a3bytes = safeReadBytes(a3, 512);

                // 同时读 args[3]+0, [3]+4, [3]+8 的一层解引用
                var a3_inner = {};
                if(a3 > 0x10000){
                    for(var off=0; off<64; off+=4){
                        try{
                            var pv = ptr(a3 + off).readU32() >>> 0;
                            if(pv > 0x10000000 && pv < 0x7FFFFFFF){
                                var d = safeReadBytes(pv, 256);
                                if(d) a3_inner['off'+off] = {ptr:'0x'+pv.toString(16), data:d};
                            }
                        }catch(e){}
                    }
                }

                var cap = {
                    n: hitCount,
                    compact: compact,
                    isFwd: isFwd,
                    hasBody: hasBody,
                    args: ['0x'+a0.toString(16),'0x'+a1.toString(16),'0x'+a2.toString(16),'0x'+a3.toString(16)],
                    a1bytes: a1bytes,
                    a3bytes: a3bytes,
                    a3_inner: a3_inner
                };
                captures.push(cap);
                send({t:'hit', n:hitCount, compact:compact, isFwd:isFwd, a3:'0x'+a3.toString(16)});
            }catch(e){}
        }
    });
    send({t:'ok', fn:'CGI_ITER'});
} catch(e){ send({t:'fail', fn:'CGI_ITER', m:e.message}); }

recv('dump', function(_){ send({t:'dump', caps:captures}); });
send({t:'ready'});
"""

captures = []
dump_event = threading.Event()
hit_event = threading.Event()

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
        print('\n' + '='*60)
        print('★★★ 请在企微转发消息！★★★')
        print('='*60)
        print('  监控：所有 args[3]≠0 的 CGI 调用（含转发）')
    elif t == 'hit':
        tag = '★ FWD!' if p['isFwd'] else '  BODY'
        print(f'  {tag} compact={p["compact"]} args[3]={p["a3"]} n={p["n"]}')
        hit_event.set()
    elif t == 'dump':
        captures.extend(p.get('caps', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 超时')
    os._exit(1)

time.sleep(3)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80): return v, pos
    return None, pos

def parse_proto_all(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 60:
        if bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag & 7; fn = tag >> 3
            if fn == 0 or fn > 5000: break
            if w == 0:
                v, i = decode_varint(bs, i)
                fields.append((fn, 'v', v))
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

def hex16(bs, n=64):
    lines = []
    for i in range(0, min(n, len(bs)), 16):
        chunk = bs[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'    {i:04x}: {h:<47}  {a}')
    return '\n'.join(lines)

print(f'\n[=== {len(captures)} 次捕获 ===]')
for ci, cap in enumerate(captures):
    print(f'\n{"="*65}')
    tag = '★FWD' if cap['isFwd'] else 'BODY'
    print(f'Cap #{ci} [{tag}]: compact={cap["compact"]} args={cap["args"]}')

    # 分析 a1bytes（compact + proto）
    if cap.get('a1bytes'):
        bs = bytes(cap['a1bytes'])
        print(f'\n  [args[1] @{cap["args"][1]}] hex:')
        print(hex16(bs, 64))
        # 跳过 compact(4B) 解析 proto
        pf = parse_proto_all(bs[4:])
        if pf:
            print(f'  proto(skip 4B compact):')
            for fn, wt, v in pf:
                if wt == 'v': print(f'    f{fn} = {v}  (0x{v:x})')
                elif wt == 's': print(f'    f{fn} = {repr(v[:80])}')
                elif wt == 'b': print(f'    f{fn} = bytes[{len(v)}]: {v[:12].hex()}')
                elif wt == 'i32': print(f'    f{fn} = i32:{v}')
                elif wt == 'i64': print(f'    f{fn} = i64:{v}')

    # 分析 a3bytes（ForwardMessageReq proto？）
    if cap.get('a3bytes') and cap['args'][3] != '0x0':
        bs = bytes(cap['a3bytes'])
        print(f'\n  [args[3] @{cap["args"][3]}] hex:')
        print(hex16(bs, 128))
        pf = parse_proto_all(bs)
        if pf:
            print(f'  proto:')
            for fn, wt, v in pf:
                if wt == 'v': print(f'    f{fn} = {v}  (0x{v:x})')
                elif wt == 's': print(f'    f{fn} = {repr(v[:80])}')
                elif wt == 'b':
                    print(f'    f{fn} = bytes[{len(v)}]: {v[:16].hex()}')
                    sub = parse_proto_all(v)
                    if len(sub) >= 2:
                        for sfn, swt, sv in sub[:10]:
                            if swt == 'v': print(f'      sub f{sfn} = {sv}')
                            elif swt == 's': print(f'      sub f{sfn} = {repr(sv[:60])}')
                elif wt == 'i32': print(f'    f{fn} = i32:{v}')
                elif wt == 'i64': print(f'    f{fn} = i64:{v}')
        else:
            print('  (无 proto 字段，可能是指针/结构体)')

    # a3 内层解引用
    inner = cap.get('a3_inner', {})
    if inner:
        print(f'\n  [args[3] 内层指针]:')
        for off, info in sorted(inner.items(), key=lambda x: int(x[0][3:])):
            bs = bytes(info['data'])
            pf = parse_proto_all(bs)
            if len(pf) >= 2:
                print(f'    {off} → {info["ptr"]}: proto({len(pf)}f)')
                for fn, wt, v in pf[:8]:
                    if wt == 'v': print(f'      f{fn}={v}')
                    elif wt == 's': print(f'      f{fn}={repr(v[:50])}')
            else:
                # hex hint
                print(f'    {off} → {info["ptr"]}: {bs[:8].hex()}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'hook_fwd_v3_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
