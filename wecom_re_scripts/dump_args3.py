# dump_args3.py
# 专门捕获 CGI_ITER args[3] (ForwardMessageReq proto) 的原始字节，
# 无过滤直接 dump 全部 proto 字段 + 原始 hex，
# 以找到 conv_id / msg_ids 的字段编号

import frida, subprocess, sys, os, time, threading, json, struct, re
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

function safeRead(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

var captures = [];
var cgiHits = 0;
var MAX_CAPS = 3;

var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            var b4 = null;
            try{ b4 = new Uint8Array(args[1].readByteArray(4)); } catch(e){}
            if(!b4 || !(b4[0]==0x01 && b4[1]==0x00 && b4[2]==0x41 && b4[3]==0x79)) return;

            cgiHits++;
            if(cgiHits > MAX_CAPS) return;

            // 读所有 args[0..5]
            var argPtrs = [];
            var argData = {};
            for(var i=0; i<6; i++){
                try{
                    var v = args[i].toInt32() >>> 0;
                    argPtrs.push('0x'+v.toString(16));
                    // 对每个 arg 读 512 字节（原始 bytes）
                    var d = safeRead(args[i], 512);
                    argData['arg'+i] = d;
                    // 深一层：读 arg[i] 指向的对象里的第一个指针，再读
                    if(d && v > 0x10000){
                        var inner = (d[0])|(d[1]<<8)|(d[2]<<16)|(d[3]<<24);
                        inner = inner >>> 0;
                        if(inner > 0x10000000 && inner < 0x7FFFFFFF){
                            var d2 = safeRead(inner, 256);
                            argData['arg'+i+'_ptr0'] = d2;
                            argData['arg'+i+'_ptr0_addr'] = '0x'+inner.toString(16);
                        }
                    }
                } catch(e){ argPtrs.push('?'); }
            }

            // 额外：读 EBP 帧 1 里的 0x33db27c8 区域（每次可能变）
            // 读 frame1 stack+0x7c (args[0]) 处的指针的对象
            var ctx = this.context;
            var ebp0 = ctx.ebp >>> 0;
            var frame1_ebp = 0;
            if(ebp0 > 8){
                var f = safeRead(ebp0, 8);
                if(f){ frame1_ebp = (f[0])|(f[1]<<8)|(f[2]<<16)|(f[3]<<24); frame1_ebp = frame1_ebp>>>0; }
            }
            var extra = {};
            if(frame1_ebp > 0x10000){
                // 读 frame1 stack+0x7c = args[0] (CGI context)
                var f1d = safeRead(frame1_ebp - 256, 512);
                if(f1d) extra['frame1_stack'] = f1d;
            }

            captures.push({
                n: cgiHits,
                args: argPtrs,
                argData: argData,
                extra: extra
            });
            send({t:'hit', n:cgiHits});
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
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:300]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'ready': print('[+] HOOKS READY!')
    elif t == 'hit':
        print(f'  ★ [HIT] n={p["n"]}')
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

print()
print('='*60)
print('★★★ 请在企微转发消息！★★★')
print('='*60)

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 超时')
    os._exit(1)

print('[+] HIT! 等 5s...')
time.sleep(5)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 工具函数 ─────────────────────────────────────────────────────────────────

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80): return v, pos
    return None, pos

def parse_proto_all(bs, label='', depth=0, indent=''):
    """解析 proto，不过滤，打印所有字段"""
    fields = []
    i = 0
    while i < len(bs) and len(fields) < 50:
        if bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag & 7
            fn = tag >> 3
            if fn == 0 or fn > 2000: break
            if w == 0:
                v, i = decode_varint(bs, i)
                fields.append((fn, 'varint', v))
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 1000000 or i2 + ln > len(bs): break
                pay = bs[i2:i2+ln]; i = i2 + ln
                try:
                    s = pay.decode('utf-8')
                    fields.append((fn, 'str', s))
                except:
                    fields.append((fn, 'bytes', pay))
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

def print_proto(bs, label, indent=''):
    fields = parse_proto_all(bs)
    if not fields:
        print(f'{indent}[{label}] 无 proto 字段')
        return
    print(f'{indent}[{label}] proto ({len(fields)} 字段):')
    for fn, wt, v in fields:
        if wt == 'varint':
            print(f'{indent}  f{fn} = {v}  (0x{v:x})')
        elif wt == 'str':
            print(f'{indent}  f{fn} = str:{repr(v[:80])}')
        elif wt == 'bytes':
            print(f'{indent}  f{fn} = bytes[{len(v)}]: {v[:16].hex()}...')
            # 尝试子 proto
            sub = parse_proto_all(v)
            if len(sub) >= 2:
                print(f'{indent}    (sub-proto):')
                for sfn, swt, sv in sub[:15]:
                    if swt == 'varint': print(f'{indent}      f{sfn} = {sv}')
                    elif swt == 'str': print(f'{indent}      f{sfn} = str:{repr(sv[:60])}')
        elif wt == 'i32':
            print(f'{indent}  f{fn} = i32:{v}  (0x{v:x})')
        elif wt == 'i64':
            print(f'{indent}  f{fn} = i64:{v}  (0x{v:x})')

def hex_dump(bs, label, n=128):
    print(f'  [{label}] raw hex ({min(n, len(bs))}B):')
    for i in range(0, min(n, len(bs)), 16):
        chunk = bs[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'    {i:04x}: {h:<47}  {a}')

# ─── 分析 ─────────────────────────────────────────────────────────────────────

print(f'\n[=== {len(captures)} 次捕获 ===]')

for ci, cap in enumerate(captures):
    print(f'\n{"="*65}')
    print(f'Cap #{ci}: args={cap.get("args", [])}')

    ad = cap.get('argData', {})

    for key in sorted(ad.keys()):
        data = ad[key]
        if not data: continue
        bs = bytes(data)
        print(f'\n--- {key} ---')
        hex_dump(bs, key, 128)
        print_proto(bs, key)

    # 特别关注 arg3（最可能是 ForwardMessageReq）
    arg3_data = ad.get('arg3')
    if arg3_data:
        bs3 = bytes(arg3_data)
        print(f'\n★ [arg3 详细分析]')
        hex_dump(bs3, 'arg3_full', 256)
        print_proto(bs3, 'arg3_proto')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'dump_args3_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
