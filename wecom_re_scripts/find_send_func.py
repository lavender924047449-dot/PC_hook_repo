# find_send_func.py: 在 MessageServiceImpl 中找 ForwardMessage 发送函数
# 用 RTTI + 函数签名分析找到 native forward API

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

# 搜索目标字符串列表
TARGETS = [
    # MessageServiceImpl 符号
    ('MessageServiceImpl_wework', '4d 65 73 73 61 67 65 53 65 72 76 69 63 65 49 6d 70 6c'),  # "MessageServiceImpl"
    # ForwardMessage + logic 命名空间
    ('ForwardMsg_logic', '46 6f 72 77 61 72 64 4d 73 67'),  # "ForwardMsg"
    ('ForwardMessage_logic', '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65'),  # "ForwardMessage"
    # 搜索 "shared_ptr@VForwardMessageReq"
    ('shared_ptr_FwdReq', '73 68 61 72 65 64 5f 70 74 72 40 56 46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71'),
    # 搜索 "SendForward" 
    ('SendForward', '53 65 6e 64 46 6f 72 77 61 72 64'),
    # SendMessage  
    ('SendMessage_method', '53 65 6e 64 4d 65 73 73 61 67 65'),
    # 搜索 logic namespace
    ('logic_wework', '6c 6f 67 69 63 40 77 65 77 6f 72 6b'),  # "logic@wework"
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
            try{ data = Array.from(new Uint8Array(h.address.sub(32).readByteArray(512))); } catch(e){}
            return {addr: h.address.toString(), data: data};
        })};
    } catch(e){
        results[name] = {count:0, err: e.message};
    }
}

// 特别扫描：找所有包含 ForwardMessage 且有 logic@wework 或 wework@@ 后缀的符号
var fwd_with_logic = [];
var msg_impl_hits = Memory.scanSync(wxBase, wxSize, '4d 65 73 73 61 67 65 53 65 72 76 69 63 65 49 6d 70 6c 40 6c 6f 67 69 63 40 77 65 77 6f 72 6b 40 40');
results.msg_service_impl = {count: msg_impl_hits.length, entries: msg_impl_hits.slice(0,10).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(128).readByteArray(512))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 搜索 "ForwardMessage" 在函数签名中（跟着 @@）
var fwd_in_sig = Memory.scanSync(wxBase, wxSize, '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65');
results.fwd_in_sig = {count: fwd_in_sig.length, entries: fwd_in_sig.slice(0,10).map(function(h){
    // 检查是否在函数签名中（前面有 ? 或后面有 @）
    try{
        var bs = h.address.sub(32).readByteArray(128);
        var s = Array.from(new Uint8Array(bs)).map(function(b){ return b>=0x20&&b<=0x7e ? String.fromCharCode(b) : '|'; }).join('');
        if(s.indexOf('@') >= 0 && (s.indexOf('@@') >= 0 || s.indexOf('wework') >= 0)){
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
        print(f'[ERR] {msg.get("description","")[:200]}')
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
done.wait(timeout=60)
sess.detach()

print(f'\n[=== 函数搜索结果 ===]')

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
            for off, st in strs[:4]:
                print(f'    +{off}: {st[:100]}')

# 找 MessageServiceImpl 的所有方法签名
print(f'\n\n=== MessageServiceImpl 方法分析 ===')
msg_impl = result_data.get('msg_service_impl', {})
print(f'MessageServiceImpl@logic@wework: {msg_impl.get("count",0)} 处')
for ei, entry in enumerate(msg_impl.get('entries', [])[:5]):
    data = entry.get('data', [])
    addr = entry.get('addr', '?')
    bs = bytes(data)
    strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]
    print(f'  @{addr}:')
    for off, s in strs[:5]:
        print(f'    +{off}: {s[:100]}')

os._exit(0)
