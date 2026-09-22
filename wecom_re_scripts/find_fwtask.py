# find_fwtask.py: 找 SyncFWMessageTask (ForWard Message Task) 的函数地址
# 以及 ConversationService::SendMessage / ForwardMessage 方法

import frida, subprocess, sys, os, time, threading, json, re, struct
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

TARGETS = [
    ('SyncFWMessageTask', '53 79 6e 63 46 57 4d 65 73 73 61 67 65 54 61 73 6b'),  # "SyncFWMessageTask"
    ('FwdTask', '46 77 64 54 61 73 6b'),  # "FwdTask"  
    ('ForwardTask', '46 6f 72 77 61 72 64 54 61 73 6b'),  # "ForwardTask"
    ('MultiForwardTask', '4d 75 6c 74 69 46 6f 72 77 61 72 64 54 61 73 6b'),
    ('forward_message', '66 6f 72 77 61 72 64 5f 6d 65 73 73 61 67 65'),  # lowercase
    # ConversationService
    ('ConversationService_SendMsg', '43 6f 6e 76 65 72 73 61 74 69 6f 6e 53 65 72 76 69 63 65'),  # ConversationService
    # SendForward
    ('SendFWMsg', '53 65 6e 64 46 57 4d 73 67'),
]

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
var wxSize = wx.size;
send({t:'info', base: wxBase.toString()});

var targets = """ + json.dumps(TARGETS) + r""";
var results = {};

for(var ti=0; ti<targets.length; ti++){
    var name = targets[ti][0];
    var pattern = targets[ti][1];
    try{
        var hits = Memory.scanSync(wxBase, wxSize, pattern);
        results[name] = {count: hits.length, entries: hits.slice(0,5).map(function(h){
            var data = [];
            try{ data = Array.from(new Uint8Array(h.address.sub(64).readByteArray(512))); } catch(e){}
            return {addr: h.address.toString(), data: data};
        })};
    } catch(e){ results[name] = {count:0, err: e.message}; }
}

// 在 RTTI 表中找所有包含 "FW" 的类
var rtti_fw = [];
var all_rtti = Memory.scanSync(wxBase, wxSize, '2e 3f 41 56');
for(var i=0; i<all_rtti.length && i<1000; i++){
    try{
        var bs = all_rtti[i].address.readByteArray(80);
        var s = Array.from(new Uint8Array(bs)).map(function(b){ return b>=0x20&&b<=0x7e ? String.fromCharCode(b) : ''; }).join('');
        if(s.indexOf('FW') >= 0 || s.indexOf('Forward') >= 0 || s.indexOf('forward') >= 0){
            rtti_fw.push({addr: all_rtti[i].address.toString(), s: s.slice(0,80)});
        }
    } catch(e){}
}
results.rtti_fw_classes = {count: rtti_fw.length, entries: rtti_fw.slice(0,20)};

// 找 MessageServiceImpl vtable 地址（找 RTTI 指针）
// RTTI Complete Object Locator 结构在 vtable[-4] 或 vtable[-1]
// 找 .?AVMessageServiceImpl@logic@wework@@
var ms_rtti_pattern = '4d 65 73 73 61 67 65 53 65 72 76 69 63 65 49 6d 70 6c 40 6c 6f 67 69 63 40 77 65 77 6f 72 6b 40 40';
var ms_rtti_hits = Memory.scanSync(wxBase, wxSize, ms_rtti_pattern);
results.MessageServiceImpl_rtti = {count: ms_rtti_hits.length, entries: ms_rtti_hits.slice(0,3).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(32).readByteArray(256))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 找 ForwardMessage 在方法名中（wework 命名空间）
var fw_method_hits = Memory.scanSync(wxBase, wxSize, '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65');
results.fwd_msg_methods = {count: fw_method_hits.length, entries: fw_method_hits.slice(0,30).map(function(h){
    try{
        // 往前找 @@ 或 ? 标志（函数签名开始）
        var pre = h.address.sub(64).readByteArray(128);
        var s = Array.from(new Uint8Array(pre)).map(function(b){ return b>=0x20&&b<=0x7e ? String.fromCharCode(b) : '|'; }).join('');
        if(s.indexOf('wework') >= 0 || s.indexOf('CRTX') >= 0){
            return {addr: h.address.toString(), s: s};
        }
        return null;
    } catch(e){ return null; }
}).filter(function(e){ return e !== null; })};

send({t:'data', r: results});
"""

result_data = {}
done = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:300]}')
        done.set()
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    if p.get('t') == 'info': print(f'  base={p["base"]}')
    elif p.get('t') == 'data':
        result_data.update(p.get('r', {}))
        done.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
done.wait(timeout=30)
sess.detach()

print(f'\n[=== 结果 ===]')

for name, info in result_data.items():
    count = info.get('count', 0)
    if count == 0: continue
    print(f'\n--- {name}: {count} 处 ---')
    
    for ei, entry in enumerate(info.get('entries', [])[:5]):
        addr = entry.get('addr', '?')
        s = entry.get('s', '')
        data = entry.get('data', [])
        
        if s:
            print(f'  #{ei} @{addr}: {s[:120]}')
        elif data:
            bs = bytes(data)
            strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]
            print(f'  #{ei} @{addr}:')
            for off, st in strs[:6]:
                print(f'    +{off}: {st[:100]}')

os._exit(0)
