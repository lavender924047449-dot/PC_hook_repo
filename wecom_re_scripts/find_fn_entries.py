# find_fn_entries.py
# 1. 从 backtrace 地址 (0x4493f2, 0x449fa7, 0x44aacd) 向后扫找函数入口 (55 8b ec)
# 2. CGI_ITER 确认 01004179 时，完整 dump a1 数据
# 3. 在转发链函数入口 hook，捕获 conv_id/msg_ids

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

// ── 1. 找函数入口：从已知地址向前扫 ──────────────────────────────────────────
// backtrace 地址 (return addresses, mid-function)
var BT_ADDRS = [0x4493f2, 0x449fa7, 0x44aacd];
var fn_entries = [];

for(var bi=0; bi<BT_ADDRS.length; bi++){
    var addr = wxBase.add(BT_ADDRS[bi]);
    // 读前 512 字节
    var code = safeRead(addr.sub(512), 600);
    if(!code){ fn_entries.push({rva:BT_ADDRS[bi], entry:null, reason:'unreadable'}); continue; }
    
    var found = null;
    // 从 512 字节处(即 addr)向前扫，找 55 8b ec
    for(var i=512; i>=3; i--){
        if(code[i-3]==0x55 && code[i-2]==0x8b && code[i-1]==0xec){
            found = i-3; break;
        }
        // 也找 53 55 8b ec (PUSH EBX + PUSH EBP)
        if(i>=4 && code[i-4]==0x53 && code[i-3]==0x55 && code[i-2]==0x8b && code[i-1]==0xec){
            found = i-4; break;
        }
        // PUSH EBP 单独的变形: 6a ff 68 ... (SEH prologue)
        if(i>=3 && code[i-3]==0x55 && code[i-2]==0x8b && code[i-1]==0xec){
            found = i-3; break;
        }
    }
    
    var entry_rva = null;
    if(found !== null){
        var entry_abs = addr.sub(512 - found);
        entry_rva = BT_ADDRS[bi] - (512 - found);
        fn_entries.push({rva: BT_ADDRS[bi], entry_rva: entry_rva, entry_abs: entry_abs.toString(),
            offset_from_entry: 512-found});
    } else {
        fn_entries.push({rva: BT_ADDRS[bi], entry_rva: null, reason:'prologue_not_found'});
    }
}
send({t:'fn_entries', entries: fn_entries});

// ── 2. CGI_ITER hook：01004179 时完整 dump a1 ────────────────────────────────
var captures = [];
var hitCount = 0;

var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            var b4 = safeRead(args[1], 4);
            if(!b4 || !(b4[0]==0x01 && b4[1]==0x00 && b4[2]==0x41 && b4[3]==0x79)) return;
            
            hitCount++;
            
            // backtrace
            var bt = [];
            try{
                bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .slice(0,20).map(function(a){ return '0x'+a.toString(16); });
            } catch(e){}
            
            // 完整读 args[1] (2048B)
            var a1_full = safeRead(args[1], 2048);
            
            // 跟踪 a1 中的所有指针（前 512B）
            var ptr_derefs = [];
            if(a1_full){
                for(var off=0; off<Math.min(512, a1_full.length); off+=4){
                    var pv = (a1_full[off]) | (a1_full[off+1]<<8) | (a1_full[off+2]<<16) | (a1_full[off+3]<<24);
                    pv = pv >>> 0;
                    if(pv > 0x10000 && pv < 0x7FFFFFFF){
                        var sub = safeRead(pv, 512);
                        if(sub) ptr_derefs.push({off:off, ptr:'0x'+pv.toString(16), data:sub});
                    }
                }
            }
            
            // 读 args[0..5]
            var arg_vals = [];
            var arg_data = [];
            for(var i=0; i<6; i++){
                try{
                    var v = args[i].toInt32() >>> 0;
                    arg_vals.push('0x'+v.toString(16));
                    arg_data.push(safeRead(args[i], 256));
                } catch(e){ arg_vals.push('?'); arg_data.push(null); }
            }
            
            captures.push({
                n: hitCount,
                backtrace: bt,
                args: arg_vals,
                a1: a1_full,
                ptr_derefs: ptr_derefs.slice(0, 30),
                arg_data: arg_data.slice(0, 4)
            });
            send({t:'hit', n:hitCount, bt:bt.length, ptrs:ptr_derefs.length});
        }
    });
    send({t:'hook_ok', fn:'CGI_ITER'});
} catch(e){ send({t:'hook_fail', fn:'CGI_ITER', m:e.message}); }

// ── 3. 根据找到的入口，动态 hook ────────────────────────────────────────────
recv('hook_entries', function(payload){
    var entries = payload.value;
    for(var ei=0; ei<entries.length; ei++){
        (function(e){
            if(!e.entry_abs) return;
            try{
                Interceptor.attach(ptr(e.entry_abs), {
                    onEnter: function(args){
                        var ecx = this.context.ecx >>> 0;
                        var argVals = [];
                        for(var i=0; i<6; i++){
                            try{ argVals.push('0x'+(args[i].toInt32()>>>0).toString(16)); }
                            catch(_){ argVals.push('?'); }
                        }
                        var thisData = safeRead(ecx, 512);
                        var ptrDerefs = [];
                        if(thisData){
                            for(var off=0; off<Math.min(128,thisData.length); off+=4){
                                var pv = (thisData[off])|(thisData[off+1]<<8)|(thisData[off+2]<<16)|(thisData[off+3]<<24);
                                pv = pv>>>0;
                                if(pv>0x10000 && pv<0x7FFFFFFF){
                                    var sub=safeRead(pv,256);
                                    if(sub) ptrDerefs.push({off:off,ptr:'0x'+pv.toString(16),data:sub});
                                }
                            }
                        }
                        captures.push({
                            n: -1, fn_rva:'0x'+e.rva.toString(16),
                            entry_rva:'0x'+e.entry_rva.toString(16),
                            ecx:'0x'+ecx.toString(16), args:argVals,
                            this: thisData,
                            ptrDerefs: ptrDerefs.slice(0,15),
                            backtrace:[], a1:null, ptr_derefs:[]
                        });
                        send({t:'fn_hit', entry_rva:'0x'+e.entry_rva.toString(16), ecx:'0x'+ecx.toString(16)});
                    }
                });
                send({t:'dynamic_hook_ok', entry: e.entry_abs});
            } catch(ex){ send({t:'dynamic_hook_fail', entry: e.entry_abs, m:ex.message}); }
        })(entries[ei]);
    }
    send({t:'entries_hooked'});
});

recv('dump', function(_){
    send({t:'dump_result', caps: captures});
});

send({t:'ready'});
"""

captures = []
dump_event = threading.Event()
hit_event = threading.Event()
fn_entries = []
entries_hooked_event = threading.Event()

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
    elif t == 'fn_entries':
        entries = p.get('entries', [])
        print(f'\n  函数入口分析:')
        for e in entries:
            rva = e.get('rva', '?')
            if e.get('entry_rva') is not None:
                off = e.get('offset_from_entry', 0)
                print(f'    RVA 0x{rva:x}: 入口 RVA 0x{e["entry_rva"]:x} (距返回地址 +0x{off:x})')
            else:
                print(f'    RVA 0x{rva:x}: {e.get("reason","?")}')
        fn_entries.extend(entries)
        # 发送 hook_entries 指令
        valid = [e for e in entries if e.get('entry_abs')]
        sc.post({'type': 'hook_entries'}, data=json.dumps(valid).encode())
    elif t == 'dynamic_hook_ok': print(f'  [OK] dynamic hook @ {p["entry"]}')
    elif t == 'dynamic_hook_fail': print(f'  [FAIL] dynamic hook @ {p.get("entry")}: {p.get("m")}')
    elif t == 'entries_hooked': 
        entries_hooked_event.set()
        print('[+] 所有入口 hooks 已设置，请转发消息！')
    elif t == 'hit':
        print(f'  ★ [CGI HIT] n={p["n"]} bt={p["bt"]} ptrs={p["ptrs"]}')
        hit_event.set()
    elif t == 'fn_hit':
        print(f'  ★ [FN HIT] entry_rva={p["entry_rva"]} ecx={p["ecx"]}')
        hit_event.set()
    elif t == 'dump_result':
        captures.extend(p.get('caps', []))
        dump_event.set()
    elif t == 'ready': print('[+] 初始化完成，分析入口中...')

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()

entries_hooked_event.wait(timeout=20)
print()
print('='*60)
print('★★★ 请在企微转发消息！★★★')
print('='*60)

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 300s 超时')
    sc.post({'type': 'dump'})
    dump_event.wait(timeout=10)
else:
    print('[+] 捕获到 Hit！等 5s...')
    time.sleep(5)
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
                except: fields.append((f,'b',pay[:12].hex()))
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

print(f'\n[=== 分析 {len(captures)} 次捕获 ===]')

for ci, cap in enumerate(captures):
    fn = cap.get('fn_rva', f'CGI#{cap.get("n","?")}')
    print(f'\n{"="*65}')
    print(f'#{ci}: {fn}  ecx={cap.get("ecx","?")}  args={cap.get("args",[][:4])}')
    
    # a1 分析
    a1 = bytes(cap.get('a1') or [])
    if a1:
        ascii_s = find_ascii(a1, 5)
        utf16_s = find_utf16(a1)
        useful_ascii = [(o,s) for o,s in ascii_s if any(c in s.lower() for c in
            ['conv','user','id','msg','room','chat','wx','ww','corp','to','from','openid','weixin','forward'])]
        if useful_ascii:
            print(f'  a1 ASCII:')
            for o,s in useful_ascii[:5]: print(f'    +{o}: {s[:80]}')
        if utf16_s:
            print(f'  a1 UTF-16:')
            for o,s in utf16_s[:5]: print(f'    +{o}: {s[:60]}')
    
    # ptr derefs 分析
    all_ptr_derefs = cap.get('ptr_derefs', []) + cap.get('ptrDerefs', [])
    found_interesting = []
    for dr in all_ptr_derefs:
        sub = bytes(dr.get('data', []))
        if not sub: continue
        ascii_s = find_ascii(sub, 4)
        utf16_s = find_utf16(sub)
        pb = parse_proto(sub)
        
        useful_ascii = [(o,s) for o,s in ascii_s if any(c in s.lower() for c in
            ['conv','user','id','msg','room','chat','wx','ww','corp','to','from','openid','weixin','forward'])]
        
        if useful_ascii or utf16_s or len(pb)>=3:
            found_interesting.append((dr, useful_ascii, utf16_s, pb))
    
    if found_interesting:
        print(f'  有趣指针 ({len(found_interesting)}):')
        for dr, useful_ascii, utf16_s, pb in found_interesting[:6]:
            print(f'\n    @ +0x{dr.get("off","?"):02x} → {dr.get("ptr","?")} ({len(bytes(dr["data"]))}B):')
            for o,s in useful_ascii[:3]: print(f'      ascii+{o}: {s[:80]}')
            for o,s in utf16_s[:2]: print(f'      utf16+{o}: {s[:60]}')
            if len(pb)>=3:
                print(f'      proto({len(pb)}f):')
                for fnum,t,v in pb[:10]:
                    if t=='v': print(f'        f{fnum}={v}')
                    elif t=='s': print(f'        f{fnum}={repr(v[:50])}')
                    elif t=='b': print(f'        f{fnum}=bytes({v})')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'fn_entries_{ts}.json'
out.write_text(json.dumps({'fn_entries':fn_entries, 'captures':captures}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
