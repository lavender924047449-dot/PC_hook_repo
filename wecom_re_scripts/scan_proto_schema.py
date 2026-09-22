# scan_proto_schema.py
# 在 WXWork 内存中扫描 ForwardMessage proto 描述符
# 目标：找 proto field names，重构 ForwardMessage schema
# 同时：在转发时扫描堆找 561B proto blob

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
var wxEnd = wxBase.add(wx.size);
send({t:'info', base: wxBase.toString(), size: '0x'+wx.size.toString(16)});

// ── 1. 扫描 ForwardMessage 字符串周围的 proto 字段名 ─────────────────────────
var FWD_MSG = Memory.scanSync(wxBase, wx.size, '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65');
send({t:'fwd_hits', n: FWD_MSG.length});

var protoFields = [];
var seen_addrs = {};

for(var i=0; i<FWD_MSG.length && i<20; i++){
    var addr = FWD_MSG[i].address;
    var key = addr.toString();
    if(seen_addrs[key]) continue;
    seen_addrs[key] = 1;
    
    // 读 64B 前 + 256B 后
    try{
        var before_bytes = [];
        try{ before_bytes = Array.from(new Uint8Array(addr.sub(64).readByteArray(64))); } catch(e){}
        var after_bytes = Array.from(new Uint8Array(addr.readByteArray(256)));
        
        var entry = {addr: addr.toString(), before: before_bytes, after: after_bytes};
        protoFields.push(entry);
    } catch(e){}
}
send({t:'proto_scan', entries: protoFields});

// ── 2. 扫描 "chat_id" "msg_id" "message_id" 等字段名 ─────────────────────────
var field_strs = ['msg_id', 'msgid', 'chat_id', 'chatid', 'target_id', 'to_user', 'touser', 'message_type', 'msgtype', 'conversation'];
var field_hits = {};

for(var fi=0; fi<field_strs.length; fi++){
    var fs = field_strs[fi];
    try{
        var pattern = fs.split('').map(function(c){ return c.charCodeAt(0).toString(16).padStart(2,'0'); }).join(' ');
        var hits = Memory.scanSync(wxBase, wx.size, pattern);
        field_hits[fs] = hits.slice(0,5).map(function(h){ 
            try{ return {addr: h.address.toString(), ctx: Array.from(new Uint8Array(h.address.sub(8).readByteArray(48)))}; }
            catch(e){ return {addr: h.address.toString()}; }
        });
    } catch(e){}
}
send({t:'field_scan', hits: field_hits});

// ── 3. Hook CGI_ITER，转发时做堆快照扫描 ─────────────────────────────────────
var FWD = {'01004179':1,'01006300':1,'01006c00':1,'01006d00':1,'01016135':1,'0161a92e':1,'01cbb414':1};
var heapScans = [];

function safeHex(p, n){ try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' '); } catch(e){ return ''; } }

var CGI_ITER = wxBase.add(0x390B39);
try {
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var b = Array.from(new Uint8Array(args[1].readByteArray(4))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
                if(!FWD[b]) return;
                send({t:'fwd', compact:b});
                
                // 读 args[1] 前 2048B + 追所有指针
                var a1b = Array.from(new Uint8Array(args[1].readByteArray(2048)));
                var pointers = [];
                for(var off=0; off+3<a1b.length; off+=4){
                    var pv = (a1b[off]) | (a1b[off+1]<<8) | (a1b[off+2]<<16) | (a1b[off+3]<<24);
                    pv = pv >>> 0;
                    if(pv > 0x10000 && pv < 0x7FFFFFFF){
                        pointers.push({off:off, v:pv.toString(16), hex: safeHex(pv, 600)});
                    }
                }
                heapScans.push({compact:b, a1:a1b, ptrs: pointers.slice(0,30)});
            } catch(e){}
        }
    });
    send({t:'ok', n:'CGI_ITER'});
} catch(e){ send({t:'err', n:'CGI_ITER', m:e.message}); }

recv('dump', function(_){
    send({t:'dump_result', scans: heapScans});
});
send({t:'ready'});
"""

proto_entries = []
field_hits = {}
heap_scans = []
dump_event = threading.Event()
fwd_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info':
        print(f'  base={p["base"]} size={p["size"]}')
    elif t == 'ok': print(f'  [OK] {p["n"]}')
    elif t == 'err': print(f'  [ERR] {p["n"]}: {p["m"]}')
    elif t == 'ready': print('[+] READY — 请转发消息！')
    elif t == 'fwd_hits': print(f'  ForwardMessage 字符串: {p["n"]} 处')
    elif t == 'proto_scan': proto_entries.extend(p.get('entries',[])); print(f'  proto entries: {len(proto_entries)}')
    elif t == 'field_scan': field_hits.update(p.get('hits',{})); print(f'  field scan done')
    elif t == 'fwd': print(f'  ★ [FWD] {p["compact"]}'); fwd_event.set()
    elif t == 'dump_result':
        heap_scans.extend(p.get('scans', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(3)

print('\n===== 静态扫描完成，等待转发... =====\n')

fwd_event.wait()
print('[+] 检测到转发！等 10 秒收集...')
time.sleep(10)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ──────────────────────────────────────────────────────────────────────
def tryPb(bs, limit=25):
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
                while i<len(bs):
                    b=bs[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                fields.append({'f':f,'t':'v','v':v})
            elif w==2:
                ln=0; sh2=0
                while i<len(bs):
                    b=bs[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                if ln>50000 or i+ln>len(bs): break
                pay=bs[i:i+ln]; i+=ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s})
                except: fields.append({'f':f,'t':'b','len':ln,'hex':pay[:32].hex()})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

print(f'\n[=== 结果 ===]')

# Proto 描述符分析
print(f'\n--- ForwardMessage 字符串上下文 ---')
for i, entry in enumerate(proto_entries[:10]):
    after = bytes(entry.get('after',[]))
    before = bytes(entry.get('before',[]))
    print(f'#{i} @ {entry.get("addr")}:')
    # after 扫描
    for m in re.finditer(rb'[\x20-\x7e]{4,}', after):
        s = m.group().decode('ascii','ignore')
        if len(s) >= 4: print(f'  after[+{m.start()}]: {s[:80]}')
    # before 扫描
    for m in re.finditer(rb'[\x20-\x7e]{4,}', before):
        s = m.group().decode('ascii','ignore')
        if len(s) >= 4 and any(kw in s.lower() for kw in ['msg','id','chat','type','user','from','to','time','forward']):
            print(f'  before[-{len(before)-m.start()}]: {s[:80]}')

# Field 名扫描
print(f'\n--- Proto 字段名搜索 ---')
for fname, hits in field_hits.items():
    if hits:
        print(f'  "{fname}": {len(hits)} 处')
        for h in hits[:2]:
            ctx = bytes(h.get('ctx',[]))
            strs = [m.group().decode('ascii','ignore') for m in re.finditer(rb'[\x20-\x7e]{4,}', ctx)]
            print(f'    @ {h["addr"]}: {" | ".join(strs[:3])}')

# Heap 扫描结果
print(f'\n--- 转发时堆数据 ---')
print(f'heap scans: {len(heap_scans)}')
for si, scan in enumerate(heap_scans[:5]):
    print(f'\n  scan#{si} compact={scan.get("compact")}')
    ptrs = scan.get('ptrs',[])
    print(f'  ptrs found: {len(ptrs)}')
    for pt in ptrs[:20]:
        h = pt.get('hex','')
        if not h: continue
        bs = bytes.fromhex(h.replace(' ',''))
        # proto?
        fields = tryPb(bs)
        if len(fields) >= 5:
            print(f'  [PROTO @ 0x{pt["v"]} via off=0x{pt["off"]:02x}] {len(fields)} fields')
            for f in fields[:10]:
                if f['t']=='s': print(f'    f{f["f"]}: {repr(f["v"][:80])}')
                elif f['t']=='v': print(f'    f{f["f"]}={f["v"]}')
                elif f['t']=='b': print(f'    f{f["f"]}(bytes,{f["len"]}): {f["hex"][:24]}')
        # 字符串?
        strs = [(m.start(),m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{6,}', bs)]
        useful = [(off,s) for off,s in strs if any(kw in s.lower() for kw in ['forward','weixin','msg','from','to','cgi','1001','compress','http','chat','openid','userid'])]
        if useful:
            print(f'  [STRINGS @ 0x{pt["v"]}]:')
            for off,s in useful[:3]: print(f'    +0x{off:03x}: {s[:80]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'proto_schema_{ts}.json'
out.write_text(json.dumps({
    'proto_entries': proto_entries,
    'field_hits': field_hits,
    'heap_scans': heap_scans,
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
