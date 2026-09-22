# stack_frame_dump.py - 在 CGI_ITER 内读 EBP 链各帧的栈数据
# 找出 conv_id 和 msg_ids（在协程栈帧中）
# 同时读 ALL args 和 a1 的 FULL 4KB + deep ptr scan

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

var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            var b4 = null;
            try{ b4 = new Uint8Array(args[1].readByteArray(4)); } catch(e){}
            if(!b4 || !(b4[0]==0x01 && b4[1]==0x00 && b4[2]==0x41 && b4[3]==0x79)) return;
            
            cgiHits++;
            
            // 读所有 args[0..7]
            var allArgs = [];
            var allArgData = [];
            for(var i=0; i<8; i++){
                try{
                    var v = args[i].toInt32() >>> 0;
                    allArgs.push('0x'+v.toString(16));
                    allArgData.push(safeRead(args[i], 1024));
                } catch(e){ allArgs.push('?'); allArgData.push(null); }
            }
            
            // EBP 链：读每个帧的完整栈数据
            var ebp = this.context.ebp >>> 0;
            var sp = this.context.esp >>> 0;
            var frameData = [];
            
            for(var fi=0; fi<8; fi++){
                if(ebp < 0x10000 || ebp > 0x7FFFFFFF) break;
                var frame = safeRead(ebp, 8);
                if(!frame) break;
                var nextEbp = (frame[0])|(frame[1]<<8)|(frame[2]<<16)|(frame[3]<<24);
                var retAddr = (frame[4])|(frame[5]<<8)|(frame[6]<<16)|(frame[7]<<24);
                nextEbp = nextEbp >>> 0; retAddr = retAddr >>> 0;
                
                // 读当前帧的栈数据（从 ebp 往上 256B + 往下 256B）
                var stackSlice = null;
                if(ebp > 256){
                    stackSlice = safeRead(ebp - 256, 512);
                }
                
                frameData.push({
                    fi: fi, ebp:'0x'+ebp.toString(16),
                    ret:'0x'+retAddr.toString(16),
                    stack: stackSlice
                });
                ebp = nextEbp;
            }
            
            captures.push({
                n: cgiHits,
                args: allArgs,
                argData: allArgData,
                frames: frameData
            });
            send({t:'hit', n:cgiHits, frames:frameData.length, args:allArgs.slice(0,4)});
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
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'ready': print('[+] HOOKS READY!')
    elif t == 'hit':
        print(f'  ★ [CGI HIT] n={p["n"]} frames={p["frames"]} args={p["args"]}')
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
print('★★★ 请转发消息！★★★')
print('='*60)

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 超时')
    os._exit(1)

print('[+] HIT！等 3s...')
time.sleep(3)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────
def find_ascii(bs, minlen=4):
    return [(m.start(), m.group().decode('ascii','ignore'))
            for m in re.finditer(rb'[\x20-\x7e]{' + str(minlen).encode() + rb',}', bs)]

def find_utf16(bs, minchars=4):
    results = []; i = 0
    while i < len(bs) - 1:
        if 0x20 <= bs[i] <= 0x7e and bs[i+1] == 0:
            start = i; j = i
            while j+1 < len(bs) and 0x20 <= bs[j] <= 0x7e and bs[j+1] == 0: j += 2
            if (j-start) >= minchars*2: results.append((start, bs[start:j].decode('utf-16-le','ignore'))); i=j; continue
        i += 1
    return results

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b&0x7F)<<sh; sh += 7
        if not(b&0x80): return v, pos
    return None, pos

def parse_proto(bs):
    fields=[]; i=0
    while i < len(bs) and len(fields)<30:
        if bs[i]==0: break
        try:
            tag,i = decode_varint(bs,i)
            if tag is None: break
            w=tag&7; f=tag>>3
            if f==0 or f>500: break
            if w==0:
                v,i = decode_varint(bs,i); fields.append((f,'v',v))
            elif w==2:
                ln,i2 = decode_varint(bs,i)
                if ln is None or ln>50000 or i2+ln>len(bs): break
                pay=bs[i2:i2+ln]; i=i2+ln
                try: s=pay.decode('utf-8'); fields.append((f,'s',s))
                except: fields.append((f,'b',pay[:12].hex()))
            elif w==5: i+=4
            elif w==1:
                if i+8<=len(bs):
                    v=struct.unpack_from('<Q',bs,i)[0]; i+=8; fields.append((f,'i64',v))
                else: break
            else: break
        except: break
    return fields

def dump_bs(bs, label='', indent=''):
    if not bs: return
    ascii_s = find_ascii(bs, 5)
    utf16_s = find_utf16(bs)
    pb = parse_proto(bs)
    
    useful_ascii = [(o,s) for o,s in ascii_s if any(c in s.lower() for c in
        ['conv','user','id','msg','room','chat','wx','ww','corp','openid','weixin',
         'forward','to','from','token','session','key','type'])]
    
    if useful_ascii or utf16_s or len(pb)>=2:
        if label: print(f'{indent}[{label}] ({len(bs)}B):')
        for o,s in useful_ascii[:5]: print(f'{indent}  ascii+{o}: {s[:80]}')
        for o,s in utf16_s[:3]: print(f'{indent}  utf16+{o}: {s[:60]}')
        if len(pb)>=2:
            print(f'{indent}  proto({len(pb)}f):')
            for fnum,t,v in pb[:15]:
                if t=='v': print(f'{indent}    f{fnum}={v}')
                elif t=='s': print(f'{indent}    f{fnum}={repr(v[:60])}')
                elif t=='i64': print(f'{indent}    f{fnum}=i64({v})')
                elif t=='b': print(f'{indent}    f{fnum}=bytes({v})')

print(f'\n[=== {len(captures)} 次捕获 ===]')

for ci, cap in enumerate(captures):
    print(f'\n{"="*65}')
    print(f'Cap #{ci}: args={cap.get("args",[])}')
    
    # 分析所有 args
    for ai, ad in enumerate(cap.get('argData', [])):
        if ad:
            dump_bs(bytes(ad), f'arg[{ai}]', '')
    
    # 分析 EBP 帧栈数据
    frames = cap.get('frames', [])
    print(f'\n  EBP 帧 ({len(frames)}):')
    for frame in frames:
        ret = frame.get('ret', '?')
        ebp = frame.get('ebp', '?')
        try:
            ra = int(ret, 16)
            if 0x2d0000 <= ra < 0x2d0000 + 0x20000000:
                rva = ra - 0x2d0000
                print(f'\n  Frame {frame["fi"]}: EBP={ebp} RET={ret} (WXWork+0x{rva:x})')
            else:
                print(f'\n  Frame {frame["fi"]}: EBP={ebp} RET={ret}')
        except: print(f'\n  Frame {frame["fi"]}: EBP={ebp} RET={ret}')
        
        stack = frame.get('stack')
        if stack:
            dump_bs(bytes(stack), f'stack[{frame["fi"]}]', '    ')
            
            # 也跟踪栈中的指针
            bs = bytes(stack)
            for off in range(0, min(256, len(bs)), 4):
                pv = (bs[off])|(bs[off+1]<<8)|(bs[off+2]<<16)|(bs[off+3]<<24)
            # 搜索栈中所有4字节对齐的非空数值
            print(f'    ptr-like values in stack:')
            for off in range(0, min(128, len(bs)), 4):
                try:
                    pv = struct.unpack_from('<I', bs, off)[0]
                    if 0x100000 < pv < 0x7FFFFFFF:
                        # Is it a WXWork address?
                        if 0x2d0000 <= pv < 0x2d0000 + 0x20000000:
                            print(f'      stack+{off:#04x}: 0x{pv:08x} (WXWork+0x{pv-0x2d0000:x})')
                        else:
                            print(f'      stack+{off:#04x}: 0x{pv:08x}')
                except: pass

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'stack_frames_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
