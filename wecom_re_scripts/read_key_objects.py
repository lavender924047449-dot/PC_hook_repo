# read_key_objects.py
# 在 CGI_ITER 触发时，深度读取关键对象：
# - args[0]/[2] = 0x3409d4c0  (CGI context)
# - args[3] = 0x33db27c8      (可能是 ForwardMessageReq)
# - 0x33ebaa10               (协程帧/转发请求)
# - 0x2b90a968               (频繁出现)
# - 0x365e586f               (Frame1 stack)

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
function safeRead2(addr, n){
    try{ return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
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
            if(cgiHits > 1) return; // 只捕一次
            
            // 读所有 args 的 4KB
            var allArgs = [];
            var allArgData = [];
            for(var i=0; i<6; i++){
                try{
                    var v = args[i].toInt32() >>> 0;
                    allArgs.push('0x'+v.toString(16));
                    allArgData.push(safeRead(args[i], 4096));
                } catch(e){ allArgs.push('?'); allArgData.push(null); }
            }
            
            // 读关键地址的 4KB（深度 scan 从栈帧发现的对象）
            var keyObjs = {};
            
            // EBP chain 收集唯一指针
            var ebp = this.context.ebp >>> 0;
            var seenPtrs = {};
            for(var fi=0; fi<8; fi++){
                if(ebp < 0x10000 || ebp > 0x7FFFFFFF) break;
                var frame = safeRead(ebp, 8);
                if(!frame) break;
                var nextEbp = (frame[0])|(frame[1]<<8)|(frame[2]<<16)|(frame[3]<<24);
                var retAddr = (frame[4])|(frame[5]<<8)|(frame[6]<<16)|(frame[7]<<24);
                nextEbp = nextEbp >>> 0; retAddr = retAddr >>> 0;
                
                // 读整个帧的栈
                if(ebp > 512){
                    var stackSlice = safeRead(ebp - 256, 512);
                    if(stackSlice){
                        // 提取所有 ptr-like 值
                        for(var off=0; off<Math.min(256, stackSlice.length); off+=4){
                            var pv = (stackSlice[off])|(stackSlice[off+1]<<8)|(stackSlice[off+2]<<16)|(stackSlice[off+3]<<24);
                            pv = pv >>> 0;
                            // 仅读堆上的对象（非栈、非WXWork代码段）
                            if(pv > 0x10000000 && pv < 0x7FFFFFFF && !seenPtrs[pv]){
                                seenPtrs[pv] = 1;
                                var d = safeRead2(pv, 2048);
                                if(d) keyObjs['0x'+pv.toString(16)] = d;
                            }
                        }
                    }
                }
                ebp = nextEbp;
            }
            
            captures.push({
                n: cgiHits,
                args: allArgs,
                argData: allArgData,
                keyObjs: keyObjs
            });
            send({t:'hit', n:cgiHits, keyObjsCount: Object.keys(keyObjs).length});
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
        print(f'  ★ [HIT] n={p["n"]} keyObjs={p["keyObjsCount"]}')
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

def parse_proto(bs, max_depth=1, depth=0):
    fields=[]; i=0
    while i < len(bs) and len(fields) < 30:
        if bs[i]==0: break
        try:
            tag,i = decode_varint(bs,i)
            if tag is None: break
            w=tag&7; f=tag>>3
            if f==0 or f>1000: break
            if w==0:
                v,i = decode_varint(bs,i); fields.append((f,'v',v))
            elif w==2:
                ln,i2 = decode_varint(bs,i)
                if ln is None or ln>1000000 or i2+ln>len(bs): break
                pay=bs[i2:i2+ln]; i=i2+ln
                try: s=pay.decode('utf-8'); fields.append((f,'s',s))
                except:
                    if depth < max_depth:
                        sub=parse_proto(pay, max_depth, depth+1)
                        if len(sub)>=2: fields.append((f,'msg',sub))
                        else: fields.append((f,'b',pay[:12].hex()))
                    else: fields.append((f,'b',pay[:12].hex()))
            elif w==5:
                if i+4<=len(bs):
                    v=struct.unpack_from('<I',bs,i)[0]; i+=4; fields.append((f,'i32',v))
                else: break
            elif w==1:
                if i+8<=len(bs):
                    v=struct.unpack_from('<Q',bs,i)[0]; i+=8; fields.append((f,'i64',v))
                else: break
            else: break
        except: break
    return fields

def is_useful_str(s):
    s_lower = s.lower()
    return any(c in s_lower for c in [
        'conv','user','id','msg','room','chat','wx','ww','corp','openid','weixin',
        'forward','to','from','token','session','key','member','contact','group',
        'file','http','cgi','proto','select', 'send', 'recv'
    ])

def dump_interesting(bs, label='', indent='  '):
    if not bs or len(bs) < 4: return False
    ascii_s = find_ascii(bs, 5)
    utf16_s = find_utf16(bs, 5)
    pb = parse_proto(bs)
    
    useful_ascii = [(o,s) for o,s in ascii_s if is_useful_str(s)]
    
    if not (useful_ascii or utf16_s or len(pb)>=3):
        return False
    
    print(f'{indent}[{label}] ({len(bs)}B):')
    for o,s in useful_ascii[:5]: print(f'{indent}  ascii+{o}: {s[:80]}')
    for o,s in utf16_s[:3]: print(f'{indent}  utf16+{o}: {s[:60]}')
    if len(pb)>=2:
        print(f'{indent}  proto({len(pb)}f):')
        for fnum,t,v in pb[:20]:
            if t=='v': print(f'{indent}    f{fnum}={v}')
            elif t=='s': print(f'{indent}    f{fnum}={repr(v[:60])}')
            elif t=='i64': print(f'{indent}    f{fnum}=i64({v})')
            elif t=='b': print(f'{indent}    f{fnum}=bytes({v})')
            elif t=='i32': print(f'{indent}    f{fnum}=i32({v})')
            elif t=='msg':
                print(f'{indent}    f{fnum}=msg{{')
                for sf in v[:8]:
                    if sf[1]=='v': print(f'{indent}      f{sf[0]}={sf[2]}')
                    elif sf[1]=='s': print(f'{indent}      f{sf[0]}={repr(sf[2][:50])}')
                    elif sf[1]=='i64': print(f'{indent}      f{sf[0]}=i64({sf[2]})')
                print(f'{indent}    }}')
    return True

print(f'\n[=== {len(captures)} 次捕获 ===]')

for ci, cap in enumerate(captures):
    print(f'\n{"="*65}')
    print(f'Cap #{ci}: args={cap.get("args",[])}')
    
    # args
    for ai, ad in enumerate(cap.get('argData', [])):
        if ad:
            dump_interesting(bytes(ad), f'arg[{ai}]@{cap.get("args",[])[ai] if ai<len(cap.get("args",[])) else "?"}', '')
    
    # keyObjs
    key_objs = cap.get('keyObjs', {})
    print(f'\n  堆对象 ({len(key_objs)}):')
    for addr, data_list in sorted(key_objs.items()):
        bs = bytes(data_list)
        found = dump_interesting(bs, f'heap@{addr}', '  ')
        if not found:
            # 还是打印一些 hex
            pass

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'key_objs_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
