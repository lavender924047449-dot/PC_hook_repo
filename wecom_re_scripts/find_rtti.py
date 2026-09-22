# find_rtti.py: 找 ForwardMessageReq RTTI + vtable + SerializeWithCachedSizes 地址
# 然后 hook SerializeWithCachedSizes 直接捕获序列化字节

import frida, subprocess, sys, os, time, threading, json, re
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID={pid}')

# RTTI 类型描述符搜索模式
# ForwardMessageReq@CRTX -> 46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71 40 43 52 54 58 40 40
TARGETS = [
    ('ForwardMessageReq@CRTX@@', '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71 40 43 52 54 58 40 40'),
    ('ForwardMessageReq@CRTX', '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71 40 43 52 54 58 40'),
    # 搜索 AppendToString (字符串方法名)
    ('AppendToString', '41 70 70 65 6e 64 54 6f 53 74 72 69 6e 67'),
    ('SerializeToString', '53 65 72 69 61 6c 69 7a 65 54 6f 53 74 72 69 6e 67'),
    ('SerializeWithCachedSizes', '53 65 72 69 61 6c 69 7a 65 57 69 74 68 43 61 63 68 65 64 53 69 7a 65 73'),
    # 搜索 "InternalSerialize" in ForwardMessageReq context
    ('InternalSerialize', '49 6e 74 65 72 6e 61 6c 53 65 72 69 61 6c 69 7a 65'),
]

JS_TEMPLATE = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
var wxEnd = wxBase.add(wx.size);
send({t:'info', base: wxBase.toString(), size: '0x'+wx.size.toString(16)});

var targets = """ + json.dumps(TARGETS) + r""";
var results = {};

for(var ti=0; ti<targets.length; ti++){
    var name = targets[ti][0];
    var pattern = targets[ti][1];
    try{
        var hits = Memory.scanSync(wxBase, wx.size, pattern);
        var entries = hits.slice(0,5).map(function(h){
            var data = [];
            try{ data = Array.from(new Uint8Array(h.address.sub(64).readByteArray(256))); } catch(e){}
            return {addr: h.address.toString(), data: data};
        });
        results[name] = {count: hits.length, entries: entries};
    } catch(e){
        results[name] = {count:0, entries:[], err: e.message};
    }
}

// 特别扫描 .?AVForwardMessageReq@CRTX@@
// MSVC RTTI: .?AV + class_name + @namespace@@ 
// 扫描 2e 3f 41 56 46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71
var rtti_pattern = '2e 3f 41 56 46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71';
var rtti_hits = Memory.scanSync(wxBase, wx.size, rtti_pattern);
results.rtti_fwdreq = {count: rtti_hits.length, entries: rtti_hits.slice(0,5).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.readByteArray(128))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 扫描 MSVC RTTI for any proto class containing "ForwardMessage"
// 2e 3f 41 56 = ".?AV" prefix
var all_rtti_hits = Memory.scanSync(wxBase, wx.size, '2e 3f 41 56');
var fwd_rtti = all_rtti_hits.filter(function(h){
    try{
        var bs = h.address.readByteArray(60);
        var s = Array.from(new Uint8Array(bs)).map(function(b){ return b>=0x20&&b<=0x7e ? String.fromCharCode(b) : ''; }).join('');
        return s.indexOf('ForwardM') >= 0;
    } catch(e){ return false; }
});
results.fwd_rtti_classes = {count: all_rtti_hits.length, fwd_count: fwd_rtti.length, entries: fwd_rtti.slice(0,10).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.readByteArray(80))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

send({t:'data', r: results});
"""

result_data = {}
done = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        done.set()
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    if p.get('t') == 'info': print(f'  base={p["base"]} size={p["size"]}')
    elif p.get('t') == 'data':
        result_data.update(p.get('r', {}))
        done.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS_TEMPLATE)
sc.on('message', on_message)
sc.load()
done.wait(timeout=30)
sess.detach()

print(f'\n[=== RTTI & 方法名搜索结果 ===]')

for name, info in result_data.items():
    count = info.get('count', 0)
    fc = info.get('fwd_count', count)
    print(f'\n{name}: {count} 处', end='')
    if 'fwd_count' in info: print(f' (Forward related: {fc})', end='')
    print()
    
    for ei, entry in enumerate(info.get('entries', [])[:3]):
        bs = bytes(entry.get('data', []))
        addr = entry.get('addr', '?')
        strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{4,}', bs)]
        print(f'  #{ei} @{addr}:')
        for off, s in strs[:4]:
            print(f'    +{off}: {s[:80]}')

# 尝试找 ForwardMessageReq 的 vtable
print('\n\n=== 找 ForwardMessageReq 的 vtable ===')

# 如果找到 RTTI 条目，vtable 通常在 typeinfo 地址前面 8 bytes 处
for entry in result_data.get('rtti_fwdreq', {}).get('entries', []):
    bs = bytes(entry.get('data', []))
    addr = entry.get('addr', '?')
    strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{4,}', bs)]
    print(f'  @{addr}:')
    for off, s in strs[:5]:
        print(f'    +{off}: {s[:80]}')

for entry in result_data.get('fwd_rtti_classes', {}).get('entries', []):
    bs = bytes(entry.get('data', []))
    addr = entry.get('addr', '?')
    s = ''.join(chr(b) if 0x20 <= b <= 0x7e else '' for b in bs)
    print(f'  @{addr}: {s[:80]}')

ts = int(time.time())
out = OUT_DIR / f'rtti_{ts}.json'
out.write_text(json.dumps({k: {'count': v.get('count',0), 'fwd_count': v.get('fwd_count'), 
                                'addr_samples': [e['addr'] for e in v.get('entries',[])[:3]]}
                            for k,v in result_data.items()}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
