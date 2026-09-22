# hook_f2top_correct.py
# 使用正确的绝对地址 ptr(0x990e58a) 挂载 f2_top
# 当 args[2]（log context）包含 "before compress" 时，
# 深度读取 args[4]（可能是 561B proto buffer）及所有指针

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

# f2_top 绝对地址（从 hook_plaintext.py 验证）
F2_TOP_ABS = 0x990e58a

# CGI_ITER 地址（用于确认转发）
CGI_ITER_ABS = 0x660B39  # wxBase.add(0x390B39) = 0x2D0000 + 0x390B39

JS = r"""
'use strict';
// 验证模块
var wx = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
});
var wxBase = wx.base;
send({t:'info', base: wxBase.toString(), f2_abs: '0x990e58a', cgi: wxBase.add(0x390B39).toString()});

function safeHex(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' '); }
    catch(e){ return ''; }
}

function safeStr(p){
    try{ return ptr(p).readCString(200) || ''; }
    catch(e){ return ''; }
}

function isAddr(v){ return v > 0x10000 && v < 0x7FFFFFFF && (v & 1) === 0; }

var beforeCompress = 'before compress';

var captures = [];
var fwdActive = false;

// Hook CGI_ITER — 标记转发活跃状态
var CGI_ITER = wxBase.add(0x390B39);
var FWD = {'01004179':1,'01006300':1,'01006c00':1,'01006d00':1,'01016135':1,'0161a92e':1,'01cbb414':1};
try {
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var b = Array.from(new Uint8Array(args[1].readByteArray(4))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
                if(FWD[b]){ fwdActive = true; send({t:'fwd_mark', compact:b}); }
            } catch(e){}
        }
    });
    send({t:'hook_ok', name:'CGI_ITER'});
} catch(e){ send({t:'hook_err', name:'CGI_ITER', msg:e.message}); }

// Hook f2_top — 使用直接绝对地址
try {
    Interceptor.attach(ptr(0x990e58a), {
        onEnter: function(args){
            if(captures.length >= 40) return;
            var rec = {ts: Date.now(), fwd: fwdActive, args_summary: []};
            
            // 扫描 args[0..7]
            var argHexes = [];
            for(var j=0; j<8; j++){
                try{
                    var av = args[j].toInt32() >>> 0;
                    var h = safeHex(args[j], 600);
                    argHexes.push({val: av, hex: h});
                    rec.args_summary.push({val: av.toString(16), hex_start: h.slice(0,48)});
                } catch(e){ argHexes.push({val:0,hex:''}); rec.args_summary.push({val:'?'}); }
            }
            
            // 检查 args[2] 是否含 "before compress"
            var a2h = argHexes[2].hex;
            var hasBefore = false;
            if(a2h){
                try{
                    var a2b = new Uint8Array(ptr(args[2]).readByteArray(600));
                    var txt = '';
                    for(var k=0; k<a2b.length; k++){
                        if(a2b[k]>=0x20 && a2b[k]<=0x7e) txt += String.fromCharCode(a2b[k]);
                        else txt += ' ';
                    }
                    hasBefore = txt.indexOf('before compress') >= 0;
                    if(hasBefore){
                        rec.a2_text = txt.slice(0, 400);
                        // 也尝试读 args[2][0x..] 找 payload 长度数字（"561"）
                        var idx = txt.indexOf('length ');
                        if(idx >= 0) rec.length_str = txt.slice(idx, idx+20);
                    }
                } catch(e){}
            }
            
            rec.has_before = hasBefore;
            
            // 深度读取 args[4]（怀疑是 payload buffer）
            try{
                var a4v = args[4].toInt32() >>> 0;
                if(isAddr(a4v)){
                    rec.arg4_hex = safeHex(args[4], 800);
                    rec.arg4_str = safeStr(args[4]);
                }
            } catch(e){}
            
            // 深度读取 args[1] 中的所有指针
            try{
                var a1b = new Uint8Array(ptr(args[1]).readByteArray(256));
                var ptr_derefs = {};
                for(var off=0; off+3<a1b.length; off+=4){
                    var pv = (a1b[off]) | (a1b[off+1]<<8) | (a1b[off+2]<<16) | (a1b[off+3]<<24);
                    pv = pv >>> 0;
                    if(isAddr(pv)){
                        var pk = pv.toString(16);
                        if(!ptr_derefs[pk]){
                            ptr_derefs[pk] = {off: off, hex: safeHex(pv, 600)};
                        }
                    }
                }
                rec.a1_ptrs = ptr_derefs;
                rec.a1_hex = safeHex(args[1], 256);
            } catch(e){}
            
            captures.push(rec);
            send({t:'f2_hit', n: captures.length, fwd: fwdActive, before: hasBefore});
            fwdActive = false;  // reset
        }
    });
    send({t:'hook_ok', name:'F2_TOP'});
} catch(e){ send({t:'hook_err', name:'F2_TOP', msg:e.message}); }

recv('dump', function(_){
    send({t:'dump_result', caps: captures});
});

send({t:'ready'});
"""

captures = []
dump_event = threading.Event()
first_hit = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info':
        print(f'  base={p["base"]}  F2_TOP=ptr(0x990e58a)  CGI_ITER={p["cgi"]}')
    elif t == 'hook_ok':
        print(f'  [OK] {p["name"]}')
    elif t == 'hook_err':
        print(f'  [ERR] {p["name"]}: {p["msg"]}')
    elif t == 'ready':
        print('[+] HOOKS READY — 请立即转发消息！（无限等待）')
    elif t == 'fwd_mark':
        print(f'  [FWD] compact={p["compact"]}')
    elif t == 'f2_hit':
        star = '★★★' if p.get('before') else ''
        print(f'  [F2 #{p["n"]}] fwd={p.get("fwd")} before={p.get("before")} {star}')
        if p.get('before'):
            first_hit.set()
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
print('★★★ 请立即在企微转发消息！（无时间限制）★★★')
print('='*60 + '\n')

first_hit.wait()
print('[+] 找到 "before compress" 调用！继续收集 30 秒...')
time.sleep(30)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ───────────────────────────────────────────────────────────────────
import struct

def tryPb(bs, limit=30):
    fields = []; i = 0
    while i < len(bs) and len(fields) < limit:
        if bs[i] == 0: break
        try:
            tag = 0; sh = 0
            while i < len(bs):
                b = bs[i]; i += 1
                tag |= (b & 0x7F) << sh; sh += 7
                if not (b & 0x80): break
                if sh > 35: raise ValueError
            w = tag & 7; f = tag >> 3
            if f == 0 or f > 3000: break
            if w == 0:
                v = 0; sh2 = 0
                while i < len(bs):
                    b = bs[i]; i += 1
                    v |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                fields.append({'f':f,'t':'v','v':v})
            elif w == 2:
                ln = 0; sh2 = 0
                while i < len(bs):
                    b = bs[i]; i += 1
                    ln |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                if ln > 100000 or i+ln > len(bs): break
                pay = bs[i:i+ln]; i += ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s,'raw':pay.hex()})
                except: fields.append({'f':f,'t':'b','len':ln,'hex':pay[:48].hex()})
            elif w == 5: i+=4; fields.append({'f':f,'t':'f32'})
            elif w == 1: i+=8; fields.append({'f':f,'t':'f64'})
            else: break
        except: break
    return fields

print(f'\n[=== RESULTS ===]  {len(captures)} total F2_TOP captures')

before_caps = [c for c in captures if c.get('has_before')]
print(f'  "before compress" captures: {len(before_caps)}')

for ci, cap in enumerate(before_caps[:5]):
    print(f'\n══ BEFORE COMPRESS #{ci} ══')
    print(f'  length_str: {cap.get("length_str","")}')
    print(f'  fwd_active: {cap.get("fwd")}')
    
    # args[4] 分析
    a4h = cap.get('arg4_hex','')
    if a4h:
        a4b = bytes.fromhex(a4h.replace(' ',''))
        print(f'\n  [args[4]] {len(a4b)}B:')
        for i in range(0, min(128, len(a4b)), 16):
            h=' '.join(f'{b:02x}' for b in a4b[i:i+16])
            c=''.join(chr(b) if 32<=b<=126 else '.' for b in a4b[i:i+16])
            print(f'    {i:04x}: {h:<48}  {c}')
        fields = tryPb(a4b)
        if len(fields) >= 3:
            print(f'  [args[4] as Protobuf: {len(fields)} fields]')
            for f in fields[:15]:
                if f['t'] == 's': print(f'    f{f["f"]}: {repr(f["v"][:80])}')
                elif f['t'] == 'b': print(f'    f{f["f"]}(bytes,{f["len"]}B): {f["hex"][:24]}')
                else: print(f'    f{f["f"]}={f.get("v","")}')
        for m in re.finditer(rb'[\x20-\x7e]{5,}', a4b):
            s = m.group().decode('ascii')
            if any(kw in s.lower() for kw in ['forward','weixin','msg','from','to','chat','cgi','http','1001','compress']):
                print(f'    STR[+0x{m.start():03x}]: {s[:80]}')
    
    # args[1] 指针 deref 分析
    ptrs = cap.get('a1_ptrs', {})
    print(f'\n  [args[1] pointers] {len(ptrs)} found')
    for addr, info in list(ptrs.items())[:10]:
        h = info.get('hex','')
        if not h: continue
        bs = bytes.fromhex(h.replace(' ',''))
        fields = tryPb(bs)
        if len(fields) >= 4:
            print(f'\n  PTR 0x{addr} [PROTO {len(fields)} fields, {len(bs)}B]:')
            for f in fields[:12]:
                if f['t'] == 's': print(f'    f{f["f"]}: {repr(f["v"][:80])}')
                elif f['t'] == 'b': print(f'    f{f["f"]}(bytes,{f["len"]}B): {f["hex"][:24]}')
                else: print(f'    f{f["f"]}={f.get("v","")}')
        for m in re.finditer(rb'[\x20-\x7e]{5,}', bs):
            s = m.group().decode('ascii')
            if any(kw in s.lower() for kw in ['forward','weixin','msg','from','to','chat','1001','compress','http']):
                print(f'    PTR 0x{addr}+0x{m.start():03x}: {s[:80]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'f2top_correct_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

os._exit(0)
