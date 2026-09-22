# capture_proto_direct.py
# 专门捕获 f2_top 的 args[4]（当其为 heap 指针时 = before-compress 缓冲区）
# 简化判断：args[4] 是有效 heap 地址 (> 0x1000000 & < 0x80000000) 且 fwd 激活

import frida, subprocess, sys, os, time, threading, json, re
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

var FWD = {'01004179':1,'01006300':1,'01006c00':1,'01006d00':1,'01016135':1,'0161a92e':1,'01cbb414':1};
var fwdActive = false;
var captures = [];
var f2Count = 0;

function safeReadBytes(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

// CGI_ITER hook
var CGI_ITER = wxBase.add(0x390B39);
try {
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var b = Array.from(new Uint8Array(args[1].readByteArray(4))).map(function(x){
                    return ('0'+x.toString(16)).slice(-2);
                }).join('');
                if(FWD[b]){
                    fwdActive = true;
                    send({t:'fwd', compact:b});
                }
            } catch(e){}
        }
    });
    send({t:'ok', n:'CGI_ITER'});
} catch(e){ send({t:'err', n:'CGI_ITER', m:e.message}); }

// F2_TOP hook
try {
    Interceptor.attach(ptr(0x990e58a), {
        onEnter: function(args){
            f2Count++;
            
            // 读所有 args[0..7]
            var argVals = [];
            for(var j=0; j<8; j++){
                try{ argVals.push(args[j].toInt32() >>> 0); }
                catch(e){ argVals.push(0); }
            }
            
            // 检查 args[2]（log 上下文）是否为有效指针
            var a2v = argVals[2];
            var a2_text = '';
            if(a2v > 0x01000000 && a2v < 0x80000000){
                var a2b = safeReadBytes(a2v, 600);
                if(a2b){
                    for(var k=0; k<a2b.length; k++){
                        if(a2b[k]>=0x20 && a2b[k]<=0x7e) a2_text += String.fromCharCode(a2b[k]);
                        else a2_text += ' ';
                    }
                }
            }
            
            var hasBefore = a2_text.indexOf('before compress') >= 0;
            
            // 检查 args[4]（payload）是否为 heap 指针
            var a4v = argVals[4];
            var isHeapPtr = a4v > 0x01000000 && a4v < 0x80000000;
            
            // 两个条件之一满足就记录：fwd 激活 OR args[4] 是 heap 指针
            var shouldCapture = (fwdActive || hasBefore) && isHeapPtr;
            
            if(shouldCapture || hasBefore){
                var rec = {
                    n: f2Count,
                    fwd: fwdActive,
                    has_before: hasBefore,
                    args: argVals
                };
                
                // 读 args[4] 1000B
                if(isHeapPtr){
                    var a4b = safeReadBytes(a4v, 1000);
                    rec.a4_hex = a4b ? a4b.map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' ') : null;
                }
                
                // 读 args[1] 2048B（CGI 上下文）
                var a1v = argVals[1];
                if(a1v > 0x01000000 && a1v < 0x80000000){
                    var a1b = safeReadBytes(a1v, 2048);
                    rec.a1_hex = a1b ? a1b.map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' ') : null;
                }
                
                // a2 text excerpt
                if(hasBefore) rec.a2_text_excerpt = a2_text.slice(0, 300);
                
                captures.push(rec);
                fwdActive = false;
                
                send({t:'captured', n:rec.n, hasBefore:hasBefore, a4v: '0x'+a4v.toString(16)});
            } else if(fwdActive){
                fwdActive = false;
            }
        }
    });
    send({t:'ok', n:'F2_TOP'});
} catch(e){ send({t:'err', n:'F2_TOP', m:e.message}); }

recv('dump', function(_){
    send({t:'dump_result', caps: captures});
});
send({t:'ready'});
"""

captures = []
dump_event = threading.Event()
fwd_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  base={p["base"]}')
    elif t == 'ok': print(f'  [OK] {p["n"]}')
    elif t == 'err': print(f'  [ERR] {p["n"]}: {p["m"]}')
    elif t == 'ready': print('[+] HOOKS READY — 请转发消息！')
    elif t == 'fwd': print(f'  ★ [FWD] {p["compact"]}'); fwd_event.set()
    elif t == 'captured': 
        bf = '★★★ BEFORE_COMPRESS' if p.get('hasBefore') else ''
        print(f'  [CAPTURED] f2#{p["n"]} a4={p["a4v"]} {bf}')
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
print('★★★ 请现在在企微转发消息！★★★')
print('='*60 + '\n')

fwd_event.wait(timeout=600)
print('[+] 检测到 FWD！等 15 秒...')
time.sleep(15)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# 分析 ──────────────────────────────────────────────────────────────────────────
def tryPb(bs, limit=30, max_field=500):
    fields=[]; i=0
    while i<len(bs) and len(fields)<limit:
        if i<len(bs) and bs[i]==0: break
        try:
            tag=0; sh=0
            while i<len(bs):
                b=bs[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                if not(b&0x80): break
                if sh>35: raise ValueError
            w=tag&7; f=tag>>3
            if f==0 or f>max_field: break
            if w==0:
                v=0; sh2=0
                while i<len(bs):
                    b=bs[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                fields.append({'f':f,'t':'v','v':v})
            elif w==2:
                ln=0; sh2=0
                while i<len(bs):
                    b=bs[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                if ln>100000 or i+ln>len(bs): break
                pay=bs[i:i+ln]; i+=ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s})
                except:
                    sub = tryPb(pay, 10)
                    fields.append({'f':f,'t':'b','len':ln,'hex':pay[:20].hex(),'sub':sub})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

def printFields(fields, indent=0):
    pfx = '  ' * indent
    for f in fields:
        if f['t']=='s': print(f'{pfx}f{f["f"]}(str): {repr(f["v"][:100])}')
        elif f['t']=='v': print(f'{pfx}f{f["f"]}(int): {f["v"]}')
        elif f['t']=='b': 
            print(f'{pfx}f{f["f"]}(bytes,{f["len"]}): {f["hex"][:40]}')
            if f.get('sub'): printFields(f['sub'], indent+1)

def findStrs(bs, min_len=5):
    return [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{'+bytes(str(min_len),'ascii')+rb',}', bs)]

def findUtf16(bs):
    results = []; i = 0
    while i < len(bs) - 1:
        if 0x20 <= bs[i] <= 0x7e and bs[i+1] == 0:
            start = i; j = i
            while j+1 < len(bs) and 0x20 <= bs[j] <= 0x7e and bs[j+1] == 0: j += 2
            if (j-start) >= 8: results.append((start, bs[start:j].decode('utf-16-le','ignore'))); i = j; continue
        i += 1
    return results

print(f'\n[=== 分析 {len(captures)} 次捕获 ===]')
for ci, cap in enumerate(captures):
    print(f'\n{"="*60}')
    print(f'Capture #{ci}: f2#{cap["n"]} fwd={cap["fwd"]} before={cap["has_before"]}')
    print(f'Args: {["0x{:08x}".format(v) for v in cap.get("args",[])[:8]]}')
    
    # 分析 a4
    a4_hex = cap.get('a4_hex')
    if a4_hex:
        a4 = bytes.fromhex(a4_hex.replace(' ',''))
        strs = findStrs(a4)
        u16 = findUtf16(a4)
        fields = tryPb(a4)
        n_str = sum(1 for f in fields if f['t']=='s')
        
        print(f'\n  args[4] ({len(a4)}B) = payload buf:')
        if strs:
            for off, s in strs[:5]: print(f'    ASCII+{off}: {s[:80]}')
        if u16:
            for off, s in u16[:5]: print(f'    UTF16+{off}: {s[:60]}')
        if len(fields) >= 3:
            print(f'    [PROTO: {len(fields)} fields, {n_str} str]')
            printFields(fields[:20], indent=2)
    
    # a2 摘录
    if cap.get('a2_text_excerpt'):
        print(f'\n  a2 excerpt: {cap["a2_text_excerpt"][:200]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'proto_direct_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
