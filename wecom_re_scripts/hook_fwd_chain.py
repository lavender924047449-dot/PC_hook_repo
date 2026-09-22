# hook_fwd_chain.py - hook 真实转发调用链
# 调用链: 0x44aacd → 0x449fa7 → 0x4493f2 → CGI_ITER(0x390B39)
# 目标: 从 0x44aacd / 0x449fa7 / 0x4493f2 读取 conv_id 和 msg_ids

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
function safeReadStr(p){
    try{ return ptr(p).readUtf8String(); }
    catch(e){ 
        try{ return ptr(p).readUtf16String(); }
        catch(e2){ return null; }
    }
}

var captures = [];
var hitEvent = false;

// 时间戳共享：转发窗口标记
var fwdActive = false;

// ── CGI_ITER：确认 01004179 并标记转发 ────────────────────────────────────────
var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var b4 = safeRead(args[1], 4);
                if(b4 && b4[0]==0x01 && b4[1]==0x00 && b4[2]==0x41 && b4[3]==0x79){
                    fwdActive = true;
                    send({t:'cgi_confirmed'});
                }
            } catch(e){}
        }
    });
    send({t:'hook_ok', fn:'CGI_ITER'});
} catch(e){ send({t:'hook_fail', fn:'CGI_ITER', m:e.message}); }

// ── 函数 0x4493f2: 直接调用 CGI_ITER ─────────────────────────────────────────
var FN_4493F2 = wxBase.add(0x4493f2);
try{
    Interceptor.attach(FN_4493F2, {
        onEnter: function(args){
            if(!fwdActive) return;
            var ecx = this.context.ecx >>> 0;
            var argVals = [];
            var argDumps = [];
            for(var i=0; i<8; i++){
                try{
                    var v = args[i].toInt32() >>> 0;
                    argVals.push('0x'+v.toString(16));
                    // 尝试读 256B
                    var d = safeRead(args[i], 256);
                    argDumps.push(d);
                } catch(e){ argVals.push('?'); argDumps.push(null); }
            }
            // 读 this (ECX) 的 1024B
            var thisData = safeRead(ecx, 1024);
            // 读 this 后续 1KB 的指针展开
            var ptrDerefs = [];
            if(thisData){
                for(var off=0; off<Math.min(256, thisData.length); off+=4){
                    var pv = (thisData[off]) | (thisData[off+1]<<8) | (thisData[off+2]<<16) | (thisData[off+3]<<24);
                    pv = pv >>> 0;
                    if(pv > 0x10000 && pv < 0x7FFFFFFF){
                        var sub = safeRead(pv, 512);
                        if(sub) ptrDerefs.push({off:off, ptr:'0x'+pv.toString(16), data:sub});
                    }
                }
            }
            captures.push({
                fn: '0x4493f2',
                ecx: '0x'+ecx.toString(16),
                args: argVals,
                this: thisData,
                ptrDerefs: ptrDerefs.slice(0, 25),
                argDumps: argDumps.slice(0, 4)
            });
            send({t:'hit', fn:'0x4493f2', ecx:'0x'+ecx.toString(16)});
            fwdActive = false;  // 只捕一次
        }
    });
    send({t:'hook_ok', fn:'0x4493f2'});
} catch(e){ send({t:'hook_fail', fn:'0x4493f2', m:e.message}); }

// ── 函数 0x449fa7: 中间层 ─────────────────────────────────────────────────────
var FN_449FA7 = wxBase.add(0x449fa7);
try{
    Interceptor.attach(FN_449FA7, {
        onEnter: function(args){
            var ecx = this.context.ecx >>> 0;
            var argVals = [];
            for(var i=0; i<6; i++){
                try{ argVals.push('0x'+(args[i].toInt32()>>>0).toString(16)); }
                catch(e){ argVals.push('?'); }
            }
            var thisData = safeRead(ecx, 512);
            captures.push({
                fn: '0x449fa7',
                ecx: '0x'+ecx.toString(16),
                args: argVals,
                this: thisData,
                ptrDerefs: []
            });
            send({t:'hit', fn:'0x449fa7', ecx:'0x'+ecx.toString(16)});
        }
    });
    send({t:'hook_ok', fn:'0x449fa7'});
} catch(e){ send({t:'hook_fail', fn:'0x449fa7', m:e.message}); }

// ── 函数 0x44aacd: 入口层 ─────────────────────────────────────────────────────
var FN_44AACD = wxBase.add(0x44aacd);
try{
    Interceptor.attach(FN_44AACD, {
        onEnter: function(args){
            var ecx = this.context.ecx >>> 0;
            var argVals = [];
            var argDumps = [];
            for(var i=0; i<8; i++){
                try{
                    var v = args[i].toInt32() >>> 0;
                    argVals.push('0x'+v.toString(16));
                    argDumps.push(safeRead(args[i], 256));
                } catch(e){ argVals.push('?'); argDumps.push(null); }
            }
            var thisData = safeRead(ecx, 1024);
            var ptrDerefs = [];
            if(thisData){
                for(var off=0; off<Math.min(256, thisData.length); off+=4){
                    var pv = (thisData[off]) | (thisData[off+1]<<8) | (thisData[off+2]<<16) | (thisData[off+3]<<24);
                    pv = pv >>> 0;
                    if(pv > 0x10000 && pv < 0x7FFFFFFF){
                        var sub = safeRead(pv, 512);
                        if(sub) ptrDerefs.push({off:off, ptr:'0x'+pv.toString(16), data:sub});
                    }
                }
            }
            captures.push({
                fn: '0x44aacd',
                ecx: '0x'+ecx.toString(16),
                args: argVals,
                this: thisData,
                ptrDerefs: ptrDerefs.slice(0, 25),
                argDumps: argDumps.slice(0, 6)
            });
            send({t:'hit', fn:'0x44aacd', ecx:'0x'+ecx.toString(16)});
        }
    });
    send({t:'hook_ok', fn:'0x44aacd'});
} catch(e){ send({t:'hook_fail', fn:'0x44aacd', m:e.message}); }

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
    elif t == 'cgi_confirmed': print('  ✓ CGI 01004179 confirmed')
    elif t == 'hit':
        print(f'  ★ [HIT] {p["fn"]} ecx={p["ecx"]}')
        hit_event.set()
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
print()

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 300s 超时')
    os._exit(1)

print('[+] 捕获到转发！等 3s...')
time.sleep(3)
sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

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
                if ln is None or ln>50000 or i2+ln>len(bs): break
                pay=bs[i2:i2+ln]; i=i2+ln
                try: s=pay.decode('utf-8'); fields.append((f,'s',s))
                except:
                    if depth<2 and ln>=2:
                        sub=parse_proto(pay,depth+1)
                        if len(sub)>=2: fields.append((f,'msg',sub))
                        else: fields.append((f,'b',pay[:12].hex()))
                    else: fields.append((f,'b',pay[:12].hex()))
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

def fmt_fields(fields, indent='  '):
    lines = []
    for f in fields:
        fn,t,v = f[0],f[1],f[2]
        if t=='v': lines.append(f'{indent}f{fn}={v}')
        elif t=='s': lines.append(f'{indent}f{fn}={repr(v[:60])}')
        elif t=='b': lines.append(f'{indent}f{fn}=bytes({v})')
        elif t=='msg':
            lines.append(f'{indent}f{fn}=msg{{')
            for sf in v[:6]: lines.extend(fmt_fields([sf], indent+'  '))
            lines.append(f'{indent}}}')
    return lines

print(f'\n[=== 分析 {len(captures)} 次捕获 ===]')

for ci, cap in enumerate(captures):
    fn = cap.get('fn', '?')
    ecx = cap.get('ecx', '?')
    args = cap.get('args', [])
    print(f'\n{"="*65}')
    print(f'#{ci}: {fn}  ECX={ecx}  args={args[:4]}')

    # this 对象扫描
    this_data = bytes(cap.get('this') or [])
    if this_data:
        ascii_s = find_ascii(this_data, minlen=5)
        utf16_s = find_utf16(this_data)
        pb = parse_proto(this_data[4:])  # skip vtable

        useful = [(o,s) for o,s in ascii_s if any(c in s.lower() for c in 
            ['conv','user','id','msg','room','chat','wx','ww','corp','to','from','openid','weixin'])]
        if useful:
            print(f'\n  this ASCII ({len(this_data)}B):')
            for o,s in useful[:6]: print(f'    +{o}: {s[:80]}')
        if utf16_s:
            print(f'  this UTF-16:')
            for o,s in utf16_s[:4]: print(f'    +{o}: {s[:60]}')
        if len(pb) >= 2:
            print(f'  this PROTO ({len(pb)}f):')
            for line in fmt_fields(pb[:12]): print(line)

    # args 扫描
    for ai, ad in enumerate(cap.get('argDumps', [])):
        if not ad: continue
        bs = bytes(ad)
        ascii_s = find_ascii(bs, minlen=5)
        utf16_s = find_utf16(bs)
        pb = parse_proto(bs)
        useful = [(o,s) for o,s in ascii_s if any(c in s.lower() for c in
            ['conv','user','id','msg','room','chat','wx','ww','corp','to','from','openid','weixin'])]
        if useful or utf16_s or len(pb)>=3:
            print(f'\n  arg[{ai}] ({args[ai] if ai<len(args) else "?"}):')
            for o,s in useful[:4]: print(f'    ascii+{o}: {s[:80]}')
            for o,s in utf16_s[:3]: print(f'    utf16+{o}: {s[:60]}')
            if len(pb)>=3:
                print(f'    proto({len(pb)}f):')
                for line in fmt_fields(pb[:8], '      '): print(line)

    # deref 指针
    derefs = cap.get('ptrDerefs', [])
    interesting_derefs = []
    for dr in derefs:
        sub = bytes(dr.get('data', []))
        if not sub: continue
        ascii_s = find_ascii(sub, minlen=5)
        utf16_s = find_utf16(sub)
        pb = parse_proto(sub)
        useful = [(o,s) for o,s in ascii_s if any(c in s.lower() for c in
            ['conv','user','id','msg','room','chat','wx','ww','corp','to','from','openid','weixin','forward'])]
        if useful or utf16_s or len(pb)>=3:
            interesting_derefs.append((dr, useful, utf16_s, pb))

    if interesting_derefs:
        print(f'\n  Interesting ptr derefs ({len(interesting_derefs)}):')
        for dr, useful, utf16_s, pb in interesting_derefs[:8]:
            print(f'\n    ptr@+0x{dr["off"]:02x} → {dr["ptr"]} ({len(bytes(dr["data"]))}B):')
            for o,s in useful[:3]: print(f'      ascii+{o}: {s[:80]}')
            for o,s in utf16_s[:2]: print(f'      utf16+{o}: {s[:60]}')
            if len(pb)>=3:
                print(f'      proto({len(pb)}f):')
                for line in fmt_fields(pb[:8], '        '): print(line)

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'fwd_chain_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
