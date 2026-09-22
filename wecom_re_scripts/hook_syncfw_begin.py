# hook_syncfw_begin.py: Hook SyncFWMessageTask::Begin，捕获 this 指针
# 分析 SyncFWMessageTask 对象找到 conv_id 和 msg_ids
# Begin 函数: RVA=0x91A2422, abs=0x9472422 (thiscall, ECX = this)

import frida, subprocess, sys, os, time, threading, json, re, struct
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

# SyncFWMessageTask::Begin 绝对地址 0x9472422
# 但是每次运行基址可能不同，需要用 RVA
# RVA = 0x9472422 - 0x2d0000 = 0x91A2422
SYNCFW_RVA = 0x91A2422

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
send({t:'info', base: wxBase.toString()});

var syncfw_abs = wxBase.add(""" + hex(SYNCFW_RVA) + r""");
send({t:'target', addr: syncfw_abs.toString()});

function safeRead(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

var captures = [];
var captureCount = 0;

try{
    Interceptor.attach(syncfw_abs, {
        onEnter: function(args){
            captureCount++;
            var thisPtr = this.context.ecx >>> 0;
            send({t:'hit', n: captureCount, this_ptr: '0x'+thisPtr.toString(16)});
            
            // 读 this 指针指向的 1024 字节
            var obj_data = safeRead(thisPtr, 1024);
            
            // 扫描 this 对象中的所有指针，跟进并读数据
            var deref_data = [];
            if(obj_data){
                for(var off=0; off<Math.min(256, obj_data.length); off+=4){
                    var pv = (obj_data[off]) | (obj_data[off+1]<<8) | (obj_data[off+2]<<16) | (obj_data[off+3]<<24);
                    pv = pv >>> 0;
                    if(pv > 0x10000 && pv < 0x80000000){
                        var sub_data = safeRead(pv, 512);
                        if(sub_data){
                            deref_data.push({off:off, v:'0x'+pv.toString(16), data: sub_data});
                        }
                    }
                }
            }
            
            captures.push({
                n: captureCount,
                this_ptr: '0x'+thisPtr.toString(16),
                this_data: obj_data,
                deref: deref_data.slice(0, 20)
            });
        }
    });
    send({t:'ok', n:'SyncFWMessageTask::Begin'});
} catch(e){ send({t:'err', m: e.message}); }

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
    t = p.get('t','')
    if t == 'info': print(f'  base={p["base"]}')
    elif t == 'target': print(f'  hook target: {p["addr"]}')
    elif t == 'ok': print(f'  [OK] {p["n"]}')
    elif t == 'err': print(f'  [ERR] {p["m"]}')
    elif t == 'ready': print('[+] HOOKS READY — 请转发消息！')
    elif t == 'hit': 
        print(f'  ★ [HIT] n={p["n"]} this={p["this_ptr"]}')
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

print('\n' + '='*60)
print('★★★ 请在企微转发消息！★★★')
print('='*60 + '\n')

got_hit = hit_event.wait(timeout=600)
if not got_hit:
    print('[!] 超时：600 秒内没有检测到转发。退出。')
    os._exit(1)
print('[+] 检测到真实 Hit！等 10 秒收集更多...')
time.sleep(10)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# 分析 ──────────────────────────────────────────────────────────────────────────
def findStrs(bs, min_len=4):
    return [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{'+str(min_len).encode()+rb',}', bs)]

def findUtf16(bs, min_chars=4):
    results = []; i = 0
    while i < len(bs) - 1:
        if 0x20 <= bs[i] <= 0x7e and bs[i+1] == 0:
            start = i; j = i
            while j+1 < len(bs) and 0x20 <= bs[j] <= 0x7e and bs[j+1] == 0: j += 2
            if (j-start) >= min_chars*2: results.append((start, bs[start:j].decode('utf-16-le','ignore'))); i = j; continue
        i += 1
    return results

def tryPb(bs, limit=20):
    fields=[]; i=0
    while i<len(bs) and len(fields)<limit:
        if bs[i]==0: break
        try:
            tag=0; sh=0
            while i<len(bs):
                b=bs[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                if not(b&0x80): break
                if sh>35: raise ValueError
            w=tag&7; f=tag>>3
            if f==0 or f>500: break
            if w==0:
                v=0; sh2=0
                while i<len(bs): b=bs[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7
                if not(b&0x80): sh2=99
                fields.append({'f':f,'t':'v','v':v})
            elif w==2:
                ln=0; sh2=0
                while i<len(bs): b=bs[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7
                if not(b&0x80): sh2=99
                if ln>50000 or i+ln>len(bs): break
                pay=bs[i:i+ln]; i+=ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s})
                except: fields.append({'f':f,'t':'b','len':ln,'hex':pay[:12].hex()})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

print(f'\n[=== 分析 {len(captures)} 次 SyncFWMessageTask::Begin ===]')

for ci, cap in enumerate(captures):
    print(f'\n{"="*60}')
    print(f'Cap #{ci}: this={cap.get("this_ptr")}')
    
    # this 对象本身
    this_data = bytes(cap.get('this_data') or [])
    if this_data:
        print(f'\n  this 对象 ({len(this_data)}B):')
        ascii_strs = findStrs(this_data)
        utf16_strs = findUtf16(this_data)
        pb_fields = tryPb(this_data[4:])  # skip vtable ptr
        
        useful_ascii = [(off,s) for off,s in ascii_strs if any(kw in s.lower() for kw in 
            ['conv','userid','user','openid','msg','room','chat','to','from','id','corp','wx','ww'])]
        
        if useful_ascii:
            print('  ASCII:')
            for off, s in useful_ascii[:8]: print(f'    +{off}: {s[:80]}')
        if utf16_strs:
            print('  UTF-16:')
            for off, s in utf16_strs[:5]: print(f'    +{off}: {s[:60]}')
        if len(pb_fields) >= 2:
            print(f'  Proto (at +4):')
            for f in pb_fields[:8]:
                if f['t']=='s': print(f'    f{f["f"]}: {repr(f["v"][:50])}')
                elif f['t']=='v': print(f'    f{f["f"]}={f["v"]}')
    
    # deref 指针
    derefs = cap.get('deref', [])
    print(f'\n  Pointer dereferences ({len(derefs)}):')
    for dr in derefs[:20]:
        sub = bytes(dr.get('data', []))
        off = dr.get('off', 0)
        v = dr.get('v', '?')
        
        ascii_strs = findStrs(sub)
        utf16_strs = findUtf16(sub)
        pb_fields = tryPb(sub)
        n_str = sum(1 for f in pb_fields if f['t']=='s')
        
        useful_ascii = [(o,s) for o,s in ascii_strs if any(kw in s.lower() for kw in 
            ['conv','userid','user','openid','msg','room','chat','id','corp','wx','ww','to','from',
             'weixin','qq.com','http','cgi','forward'])]
        
        if useful_ascii or utf16_strs or len(pb_fields) >= 3:
            print(f'\n    ptr@+0x{off:02x} → {v} ({len(sub)}B):')
            for o, s in useful_ascii[:4]: print(f'      ASCII+{o}: {s[:80]}')
            for o, s in utf16_strs[:3]: print(f'      UTF16+{o}: {s[:60]}')
            if len(pb_fields) >= 3:
                print(f'      [PROTO {len(pb_fields)}f, {n_str}str]:')
                for f in pb_fields[:8]:
                    if f['t']=='s': print(f'        f{f["f"]}: {repr(f["v"][:50])}')
                    elif f['t']=='v': print(f'        f{f["f"]}={f["v"]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'syncfw_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
