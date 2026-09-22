# deep_proto_hunt.py
# 在所有 CGI_ITER 调用里，走路径 a1+0x10→+0x30 读嵌套对象
# 解析为 proto，找含 conv_id 的 ForwardMessageReq
# 无 compact 过滤，一旦找到 f13 字段就报告

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

function safeR4(addr){
    try{ return ptr(addr).readU32() >>> 0; }
    catch(e){ return 0; }
}
function safeReadBytes(addr, n){
    try{ return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e){ return null; }
}

var hits = [];
var hitCount = 0;
var MAX_HITS = 20;
var seenProtos = {}; // dedup by proto bytes

var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var a1v = args[1].toInt32() >>> 0;
                if(a1v < 0x10000) return;

                // compact
                var compact = '????????';
                try{
                    var cb = new Uint8Array(args[1].readByteArray(4));
                    compact = ('0'+cb[0].toString(16)).slice(-2)+('0'+cb[1].toString(16)).slice(-2)
                            + ('0'+cb[2].toString(16)).slice(-2)+('0'+cb[3].toString(16)).slice(-2);
                }catch(e){}

                // 路径 a1+0x10 → follow → +0x30 → proto
                // (来自 wait_cap 分析：root+0x10→+0x30 = ForwardMessageReq)
                var OFFSETS = [
                    [0x10, 0x28], [0x10, 0x2c], [0x10, 0x30], [0x10, 0x34],
                    [0x14, 0x28], [0x14, 0x2c], [0x14, 0x30], [0x14, 0x34],
                    [0x18, 0x28], [0x18, 0x30],
                    [0x20, 0x28], [0x20, 0x30], [0x20, 0x34],
                ];

                for(var oi=0; oi<OFFSETS.length; oi++){
                    var off1 = OFFSETS[oi][0], off2 = OFFSETS[oi][1];
                    var p1 = safeR4(a1v + off1);
                    if(p1 < 0x10000000 || p1 > 0x7FFFFFFF) continue;
                    var p2 = safeR4(p1 + off2);
                    if(p2 < 0x10000000 || p2 > 0x7FFFFFFF) continue;

                    // 读 p2 处 256 字节，尝试解析 proto 寻找 f13
                    var bs = safeReadBytes(p2, 256);
                    if(!bs) continue;

                    // 快速解析 varint proto，寻找 f13（tag=0x68, value≠0）
                    // f13 varint tag = (13<<3)|0 = 0x68
                    var found_f13 = -1;
                    var i = 0;
                    var safety = 0;
                    while(i < bs.length && safety++ < 200){
                        if(bs[i] === 0) break;
                        // 读 tag varint
                        var tag = 0, sh = 0;
                        while(i < bs.length){
                            var b = bs[i++];
                            tag |= (b&0x7f) << sh; sh += 7;
                            if(!(b&0x80)) break;
                        }
                        var w = tag & 7, fn = tag >> 3;
                        if(fn === 0 || fn > 2000) break;
                        if(w === 0){
                            var v = 0; sh = 0;
                            while(i < bs.length){
                                var b = bs[i++];
                                v |= (b&0x7f) << sh; sh += 7;
                                if(!(b&0x80)) break;
                            }
                            if(fn === 13 && v > 0){ found_f13 = v; break; }
                            // 也记录 f11 等
                        } else if(w === 2){
                            var ln = 0; sh = 0;
                            var i0 = i;
                            while(i < bs.length){
                                var b = bs[i++];
                                ln |= (b&0x7f) << sh; sh += 7;
                                if(!(b&0x80)) break;
                            }
                            if(ln < 0 || ln > 100000 || i+ln > bs.length) break;
                            i += ln;
                        } else if(w === 5){ i += 4; }
                        else if(w === 1){ i += 8; }
                        else break;
                    }

                    if(found_f13 > 0 && hitCount < MAX_HITS){
                        hitCount++;
                        // 也读 args[3] 的 256 字节
                        var a3bytes = null;
                        try{ a3bytes = safeReadBytes(args[3], 256); }catch(e){}
                        hits.push({
                            n: hitCount,
                            compact: compact,
                            a1: '0x'+a1v.toString(16),
                            path: 'a1+0x'+off1.toString(16)+'→+0x'+off2.toString(16),
                            p1: '0x'+p1.toString(16),
                            p2: '0x'+p2.toString(16),
                            proto_bytes: bs,
                            a3: '0x'+(args[3].toInt32()>>>0).toString(16),
                            a3bytes: a3bytes
                        });
                        send({t:'hit', n:hitCount, compact:compact, f13:found_f13,
                              path:'a1+0x'+off1.toString(16)+'→+0x'+off2.toString(16),
                              p2:'0x'+p2.toString(16)});
                    }
                }
            }catch(e){}
        }
    });
    send({t:'ok', fn:'CGI_ITER'});
} catch(e){ send({t:'fail', fn:'CGI_ITER', m:e.message}); }

recv('dump', function(_){ send({t:'dump', hits:hits}); });
send({t:'ready'});
"""

captured = []
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
        print('  (会自动检测 f13 字段，找到就报告)')
    elif t == 'hit':
        print(f'  ★ HIT! compact={p["compact"]} f13={p["f13"]} path={p["path"]} p2={p["p2"]}')
        hit_event.set()
    elif t == 'dump':
        captured.extend(p.get('hits', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 超时 - 没有找到含 f13 的 proto')
    os._exit(1)

time.sleep(5)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────
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
                v, i = decode_varint(bs, i)
                if v is None: break
                fields.append((fn, 'v', v))
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 500000 or i2+ln > len(bs): break
                pay = bs[i2:i2+ln]; i = i2+ln
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

print(f'\n[=== {len(captured)} 次捕获 ===]')

for ci, cap in enumerate(captured):
    print(f'\n{"="*65}')
    print(f'Cap #{ci}: compact={cap["compact"]} path={cap["path"]}')
    print(f'  a1={cap["a1"]} p1={cap["p1"]} p2={cap["p2"]} a3={cap["a3"]}')

    bs = bytes(cap['proto_bytes'])
    h = ' '.join(f'{b:02x}' for b in bs[:48])
    print(f'  proto_bytes[0:48]: {h}')
    fields = parse_proto(bs)
    if fields:
        print(f'  ALL proto 字段:')
        for fn, wt, v in fields:
            if wt == 'v': print(f'    f{fn} = {v}  (0x{v:x})')
            elif wt == 's': print(f'    f{fn} = str:{repr(v[:80])}')
            elif wt == 'b':
                print(f'    f{fn} = bytes[{len(v)}]: {v[:16].hex()}')
                sub = parse_proto(v)
                if sub:
                    for sfn, swt, sv in sub[:6]:
                        if swt == 'v': print(f'      sub f{sfn}={sv}')
                        elif swt == 's': print(f'      sub f{sfn}={repr(sv[:40])}')
            elif wt == 'i32': print(f'    f{fn} = i32:{v}  (0x{v:x})')
            elif wt == 'i64': print(f'    f{fn} = i64:{v}  (0x{v:x})')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'deep_proto_{ts}.json'
out.write_text(json.dumps(captured, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
