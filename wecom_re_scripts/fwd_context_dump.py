# fwd_context_dump.py
# 检测到 fwd 标记，立即 dump 前 10 + 后 5 次 f2_top 调用的所有 args
# 无限等待，用户转发后自动保存并分析

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
var wx = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
});
var wxBase = wx.base;
send({t:'info', base: wxBase.toString()});

function safeHex(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' '); }
    catch(e){ return ''; }
}

var FWD = {'01004179':1,'01006300':1,'01006c00':1,'01006d00':1,'01016135':1,'0161a92e':1,'01cbb414':1};

// 环形缓冲区存储最近 20 次 f2_top 调用
var ringBuf = [];
var RING_SIZE = 20;
var fwdPending = false;
var afterFwdCount = 0;
var triggered = false;
var dumpCaps = [];

// CGI_ITER
var CGI_ITER = wxBase.add(0x390B39);
try {
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var b = Array.from(new Uint8Array(args[1].readByteArray(4))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
                if(FWD[b]){
                    fwdPending = true;
                    afterFwdCount = 0;
                    send({t:'fwd', compact:b, ring_size: ringBuf.length});
                }
            } catch(e){}
        }
    });
    send({t:'ok', n:'CGI_ITER'});
} catch(e){ send({t:'err', n:'CGI_ITER', m:e.message}); }

// F2_TOP (正确绝对地址)
try {
    Interceptor.attach(ptr(0x990e58a), {
        onEnter: function(args){
            var rec = {ts: Date.now(), fwd: fwdPending, args: []};
            
            // 读 args[0..7]
            for(var j=0; j<8; j++){
                try{
                    var av = args[j].toInt32() >>> 0;
                    var h = safeHex(args[j], 1024);
                    rec.args.push({v: av, h: h});
                } catch(e){ rec.args.push({v:0, h:''}); }
            }
            
            // 加入环形缓冲
            ringBuf.push(rec);
            if(ringBuf.length > RING_SIZE) ringBuf.shift();
            
            // 如果刚有 fwd，开始收集后续
            if(fwdPending){
                fwdPending = false;
                send({t:'f2_fwd', n: ringBuf.length});
                // 继续收集 5 次后
                afterFwdCount = 5;
            } else if(afterFwdCount > 0){
                afterFwdCount--;
                if(afterFwdCount === 0 && !triggered){
                    triggered = true;
                    // dump ring buffer
                    for(var i=0; i<ringBuf.length; i++){
                        dumpCaps.push(ringBuf[i]);
                    }
                    send({t:'dump_now', n: dumpCaps.length});
                }
            }
        }
    });
    send({t:'ok', n:'F2_TOP'});
} catch(e){ send({t:'err', n:'F2_TOP', m:e.message}); }

recv('dump', function(_){
    var final_ring = ringBuf.slice();
    for(var i=0; i<final_ring.length; i++) dumpCaps.push(final_ring[i]);
    send({t:'dump_result', caps: dumpCaps});
});

send({t:'ready'});
"""

dump_buf = []
dump_event = threading.Event()
fwd_triggered = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info':
        print(f'  base={p["base"]}')
    elif t == 'ok':
        print(f'  [OK] {p["n"]}')
    elif t == 'err':
        print(f'  [ERR] {p["n"]}: {p["m"]}')
    elif t == 'ready':
        print('[+] HOOKS READY — 请转发！')
    elif t == 'fwd':
        print(f'  ★ [FWD] compact={p["compact"]}  ring={p["ring_size"]}')
        fwd_triggered.set()
    elif t == 'f2_fwd':
        print(f'  [F2_FWD] after fwd, ring={p["n"]}')
    elif t == 'dump_now':
        print(f'  [DUMP] {p["n"]} captures in ring')
    elif t == 'dump_result':
        dump_buf.extend(p.get('caps', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print('\n' + '='*60)
print('★★★ 请转发消息！（无限等待）★★★')
print('='*60 + '\n')

fwd_triggered.wait()
print('[+] FWD 触发！等待 15 秒收集后续...')
time.sleep(20)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────
import struct

print(f'\n[=== DUMP: {len(dump_buf)} captures ===]')

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
            if f==0 or f>3000: break
            if w==0:
                v=0; sh2=0
                while i<len(bs): b=bs[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7; (not(b&0x80)) and (sh2:=99)
                fields.append({'f':f,'t':'v','v':v})
            elif w==2:
                ln=0; sh2=0
                while i<len(bs): b=bs[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7; (not(b&0x80)) and (sh2:=99)
                if ln>50000 or i+ln>len(bs): break
                pay=bs[i:i+ln]; i+=ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s})
                except: fields.append({'f':f,'t':'b','len':ln,'hex':pay[:32].hex()})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

for ci, cap in enumerate(dump_buf):
    fwd_mark = '  ← FWD' if cap.get('fwd') else ''
    print(f'\n── cap#{ci}{fwd_mark} ──')
    
    for ai, arg in enumerate(cap.get('args', [])[:8]):
        h = arg.get('h','')
        v = arg.get('v',0)
        if not h: 
            print(f'  arg[{ai}]={v}')
            continue
        bs = bytes.fromhex(h.replace(' ',''))
        
        # 扫描字符串（找所有关键字，不只 before compress）
        found_kw = []
        for m in re.finditer(rb'[\x20-\x7e]{6,}', bs):
            s = m.group().decode('ascii')
            for kw in ['before','after','compress','cgi','weixin','forward','1001','http','msg','from','to','uuid','ChatReq','key']:
                if kw.lower() in s.lower():
                    found_kw.append(f'+0x{m.start():03x}:{s[:60]}')
                    break
        
        # proto?
        fields = tryPb(bs)
        n_str_fields = sum(1 for f in fields if f.get('t')=='s')
        
        # UUID?
        has_uuid = bool(re.search(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', bs))
        
        label = f'v=0x{v:08x}'
        if found_kw: label += f'  [KW:{len(found_kw)}]'
        if len(fields) >= 3: label += f'  [PROTO:{len(fields)}f,{n_str_fields}s]'
        if has_uuid: label += '  [UUID]'
        print(f'  arg[{ai}] {label}')
        for kw in found_kw[:4]:
            print(f'    {kw}')
        if len(fields) >= 3:
            for f in fields[:6]:
                if f.get('t')=='s': print(f'    f{f["f"]}: {repr(f["v"][:60])}')
                elif f.get('t')=='v': print(f'    f{f["f"]}={f["v"]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'fwd_ctx_{ts}.json'
out.write_text(json.dumps(dump_buf, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
