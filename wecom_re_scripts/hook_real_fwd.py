# hook_real_fwd.py - hook 真实转发函数入口（已确定地址）
# 函数入口: 0x4493c0, 0x449f60, 0x44aaa0
# CGI_ITER: 0x390B39（读 args[1]，compact=01004179）

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
var hitCount = 0;

// ── CGI_ITER: 确认 01004179 并 dump 完整 a1 ──────────────────────────────────
var CGI_ITER = wxBase.add(0x390B39);
var lastFwdTime = 0;
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            var b4 = safeRead(args[1], 4);
            if(!b4 || !(b4[0]==0x01 && b4[1]==0x00 && b4[2]==0x41 && b4[3]==0x79)) return;
            lastFwdTime = Date.now();
            hitCount++;
            
            var bt = [];
            try{
                bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0,25).map(function(a){ return '0x'+a.toString(16); });
            } catch(e){}
            
            var a1_full = safeRead(args[1], 4096);
            var ptr_derefs = [];
            if(a1_full){
                for(var off=0; off<Math.min(512, a1_full.length); off+=4){
                    var pv = (a1_full[off]) | (a1_full[off+1]<<8) | (a1_full[off+2]<<16) | (a1_full[off+3]<<24);
                    pv = pv >>> 0;
                    if(pv > 0x10000 && pv < 0x7FFFFFFF){
                        var sub = safeRead(pv, 1024);
                        if(sub) ptr_derefs.push({off:off, ptr:'0x'+pv.toString(16), data:sub});
                    }
                }
            }
            
            // 也读 args[0,2,3,4]
            var arg_extra = [];
            for(var i=0; i<6; i++){
                if(i==1) { arg_extra.push(null); continue; }
                arg_extra.push(safeRead(args[i], 512));
            }
            
            captures.push({
                src:'cgi', n:hitCount, backtrace:bt,
                a1: a1_full, ptr_derefs: ptr_derefs.slice(0, 40),
                arg_extra: arg_extra
            });
            send({t:'cgi_hit', n:hitCount, ptrs:ptr_derefs.length});
        }
    });
    send({t:'hook_ok', fn:'CGI_ITER'});
} catch(e){ send({t:'hook_fail', fn:'CGI_ITER', m:e.message}); }

// ── FN 0x4493c0: 直接调用 CGI 的函数 ────────────────────────────────────────
var FN1 = wxBase.add(0x4493c0);
try{
    Interceptor.attach(FN1, {
        onEnter: function(args){
            var ecx = this.context.ecx >>> 0;
            var argVals = [];
            var argData = [];
            for(var i=0; i<8; i++){
                try{
                    var v = args[i].toInt32()>>>0;
                    argVals.push('0x'+v.toString(16));
                    argData.push(safeRead(args[i], 512));
                } catch(e){ argVals.push('?'); argData.push(null); }
            }
            var thisD = safeRead(ecx, 1024);
            var ptrD = [];
            if(thisD){
                for(var off=0; off<Math.min(256, thisD.length); off+=4){
                    var pv=(thisD[off])|(thisD[off+1]<<8)|(thisD[off+2]<<16)|(thisD[off+3]<<24);
                    pv=pv>>>0;
                    if(pv>0x10000 && pv<0x7FFFFFFF){
                        var sub=safeRead(pv, 512);
                        if(sub) ptrD.push({off:off, ptr:'0x'+pv.toString(16), data:sub});
                    }
                }
            }
            captures.push({
                src:'fn1', fn:'0x4493c0',
                ecx:'0x'+ecx.toString(16), args:argVals,
                this: thisD, ptrDerefs: ptrD.slice(0,20),
                argData: argData.slice(0,6)
            });
            send({t:'fn_hit', fn:'0x4493c0', ecx:'0x'+ecx.toString(16)});
        }
    });
    send({t:'hook_ok', fn:'0x4493c0'});
} catch(e){ send({t:'hook_fail', fn:'0x4493c0', m:e.message}); }

// ── FN 0x449f60 ───────────────────────────────────────────────────────────────
var FN2 = wxBase.add(0x449f60);
try{
    Interceptor.attach(FN2, {
        onEnter: function(args){
            var ecx = this.context.ecx >>> 0;
            var argVals = [];
            var argData = [];
            for(var i=0; i<8; i++){
                try{
                    argVals.push('0x'+(args[i].toInt32()>>>0).toString(16));
                    argData.push(safeRead(args[i], 512));
                } catch(e){ argVals.push('?'); argData.push(null); }
            }
            var thisD = safeRead(ecx, 1024);
            var ptrD = [];
            if(thisD){
                for(var off=0; off<Math.min(256, thisD.length); off+=4){
                    var pv=(thisD[off])|(thisD[off+1]<<8)|(thisD[off+2]<<16)|(thisD[off+3]<<24);
                    pv=pv>>>0;
                    if(pv>0x10000 && pv<0x7FFFFFFF){
                        var sub=safeRead(pv,512);
                        if(sub) ptrD.push({off:off, ptr:'0x'+pv.toString(16), data:sub});
                    }
                }
            }
            captures.push({
                src:'fn2', fn:'0x449f60',
                ecx:'0x'+ecx.toString(16), args:argVals,
                this: thisD, ptrDerefs: ptrD.slice(0,20),
                argData: argData.slice(0,6)
            });
            send({t:'fn_hit', fn:'0x449f60', ecx:'0x'+ecx.toString(16)});
        }
    });
    send({t:'hook_ok', fn:'0x449f60'});
} catch(e){ send({t:'hook_fail', fn:'0x449f60', m:e.message}); }

// ── FN 0x44aaa0 ───────────────────────────────────────────────────────────────
var FN3 = wxBase.add(0x44aaa0);
try{
    Interceptor.attach(FN3, {
        onEnter: function(args){
            var ecx = this.context.ecx >>> 0;
            var argVals = [];
            var argData = [];
            for(var i=0; i<8; i++){
                try{
                    argVals.push('0x'+(args[i].toInt32()>>>0).toString(16));
                    argData.push(safeRead(args[i], 512));
                } catch(e){ argVals.push('?'); argData.push(null); }
            }
            var thisD = safeRead(ecx, 1024);
            var ptrD = [];
            if(thisD){
                for(var off=0; off<Math.min(256, thisD.length); off+=4){
                    var pv=(thisD[off])|(thisD[off+1]<<8)|(thisD[off+2]<<16)|(thisD[off+3]<<24);
                    pv=pv>>>0;
                    if(pv>0x10000 && pv<0x7FFFFFFF){
                        var sub=safeRead(pv,512);
                        if(sub) ptrD.push({off:off, ptr:'0x'+pv.toString(16), data:sub});
                    }
                }
            }
            captures.push({
                src:'fn3', fn:'0x44aaa0',
                ecx:'0x'+ecx.toString(16), args:argVals,
                this: thisD, ptrDerefs: ptrD.slice(0,20),
                argData: argData.slice(0,6)
            });
            send({t:'fn_hit', fn:'0x44aaa0', ecx:'0x'+ecx.toString(16)});
        }
    });
    send({t:'hook_ok', fn:'0x44aaa0'});
} catch(e){ send({t:'hook_fail', fn:'0x44aaa0', m:e.message}); }

recv('dump', function(_){
    send({t:'dump_result', caps: captures});
});

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
    elif t == 'hook_ok': print(f'  [OK] {p["fn"]}')
    elif t == 'hook_fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'cgi_hit':
        print(f'  ★ [CGI HIT] n={p["n"]} ptrs={p["ptrs"]}')
        hit_event.set()
    elif t == 'fn_hit':
        print(f'  ★ [FN HIT] {p["fn"]} ecx={p["ecx"]}')
        hit_event.set()
    elif t == 'ready': print('[+] HOOKS READY!')
    elif t == 'dump_result':
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
    print('[!] 300s 超时')
    sc.post({'type': 'dump'})
    dump_event.wait(timeout=5)
else:
    print('[+] HIT！等 3s 收集...')
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

def parse_proto(bs, depth=0):
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
                if ln is None or ln>100000 or i2+ln>len(bs): break
                pay=bs[i2:i2+ln]; i=i2+ln
                try: s=pay.decode('utf-8'); fields.append((f,'s',s))
                except:
                    if depth<2 and len(pay)>=2:
                        sub=parse_proto(pay,depth+1)
                        if len(sub)>=2: fields.append((f,'msg',sub))
                        else: fields.append((f,'b',pay[:12].hex()))
                    else: fields.append((f,'b',pay[:12].hex()))
            elif w==5: i+=4
            elif w==1:
                if i+8<=len(bs):
                    v=struct.unpack_from('<Q', bs, i)[0]; i+=8
                    fields.append((f,'i64',v))
                else: break
            else: break
        except: break
    return fields

def dump_interesting(bs, label='', indent='  '):
    if not bs: return
    ascii_s = find_ascii(bs, 5)
    utf16_s = find_utf16(bs)
    pb = parse_proto(bs)
    
    useful_ascii = [(o,s) for o,s in ascii_s if any(c in s.lower() for c in
        ['conv','user','id','msg','room','chat','wx','ww','corp','to','from','openid','weixin',
         'forward','cgi','type','token','session'])]
    
    if useful_ascii or utf16_s or len(pb)>=2:
        if label: print(f'\n{indent}[{label}] ({len(bs)}B):')
        for o,s in useful_ascii[:5]: print(f'{indent}  ascii+{o}: {s[:80]}')
        for o,s in utf16_s[:3]: print(f'{indent}  utf16+{o}: {s[:60]}')
        if len(pb)>=2:
            print(f'{indent}  proto({len(pb)}f):')
            for fnum,t,v in pb[:15]:
                if t=='v': print(f'{indent}    f{fnum}={v}')
                elif t=='s': print(f'{indent}    f{fnum}={repr(v[:60])}')
                elif t=='i64': print(f'{indent}    f{fnum}=i64({v})')
                elif t=='b': print(f'{indent}    f{fnum}=bytes({v})')
                elif t=='msg':
                    print(f'{indent}    f{fnum}=msg{{')
                    for sf in v[:6]:
                        sfn,st,sv = sf
                        if st=='v': print(f'{indent}      f{sfn}={sv}')
                        elif st=='s': print(f'{indent}      f{sfn}={repr(sv[:40])}')
                        elif st=='i64': print(f'{indent}      f{sfn}=i64({sv})')
                    print(f'{indent}    }}')

print(f'\n[=== 分析 {len(captures)} 次捕获 ===]')

# 过滤：优先显示 fn 捕获（对应具体函数），再显示 cgi 捕获
fn_caps = [c for c in captures if c.get('src') in ('fn1','fn2','fn3')]
cgi_caps = [c for c in captures if c.get('src') == 'cgi']

print(f'\nCGI 捕获: {len(cgi_caps)}, FN 捕获: {len(fn_caps)}')

for ci, cap in enumerate(cgi_caps[:3]):
    print(f'\n{"="*65}')
    print(f'[CGI #{cap.get("n")}] ptrs={len(cap.get("ptr_derefs",[]))}')
    
    a1 = bytes(cap.get('a1') or [])
    if a1:
        print(f'\n  a1 ({len(a1)}B) 有趣内容:')
        dump_interesting(a1, '', '  ')
    
    for dr in cap.get('ptr_derefs', [])[:30]:
        sub = bytes(dr.get('data', []))
        dump_interesting(sub, f'ptr@+0x{dr.get("off","?"):02x}→{dr.get("ptr","?")}', '  ')

for ci, cap in enumerate(fn_caps[:6]):
    fn = cap.get('fn', '?')
    print(f'\n{"="*65}')
    print(f'[{fn}] ECX={cap.get("ecx")}')
    print(f'  args={cap.get("args",[][:5])}')
    
    # this
    this_d = bytes(cap.get('this') or [])
    dump_interesting(this_d, 'this', '')
    
    # args
    for ai, ad in enumerate(cap.get('argData', [])):
        if ad: dump_interesting(bytes(ad), f'arg[{ai}]', '')
    
    # ptrDerefs
    for dr in cap.get('ptrDerefs', [])[:20]:
        sub = bytes(dr.get('data', []))
        dump_interesting(sub, f'ptr@+0x{dr.get("off","?"):02x}→{dr.get("ptr","?")}', '  ')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'hook_real_fwd_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
