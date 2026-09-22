# hook_syncfw.py: Hook SyncFWMessageTask::Begin（或Execute）
# "[SyncFWMessageTask] begin" 的引用地址就是 Begin 方法
# 分析其参数，找 conv_id 和 msg_ids

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

# 已知地址：SyncFWMessageTask 日志字符串在 0xb777e0d + 63 = 0xb777e4c
# "[SyncFWMessageTask] begin" 字符串地址需要找

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
var wxSize = wx.size;
var wxBase_n = wxBase.toInt32() >>> 0;
send({t:'info', base: wxBase.toString()});

var results = {};

// 1. 找 "[SyncFWMessageTask] begin" 字符串地址
var begin_pattern = '5b 53 79 6e 63 46 57 4d 65 73 73 61 67 65 54 61 73 6b 5d 20 62 65 67 69 6e';
var begin_hits = Memory.scanSync(wxBase, wxSize, begin_pattern);
results.begin_str = {count: begin_hits.length, addrs: begin_hits.slice(0,3).map(function(h){ return h.address.toString(); })};

// 2. 找引用 "[SyncFWMessageTask] begin" 字符串的代码
// 该字符串地址会以 little-endian 形式出现在某个 CALL 或 MOV 指令附近
if(begin_hits.length > 0){
    var str_addr = begin_hits[0].address.toInt32() >>> 0;
    var str_le = [str_addr & 0xff, (str_addr >> 8) & 0xff, (str_addr >> 16) & 0xff, (str_addr >> 24) & 0xff];
    var str_pattern = str_le.map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ');
    var ref_hits = Memory.scanSync(wxBase, wxSize, str_pattern);
    results.begin_refs = {count: ref_hits.length, entries: ref_hits.slice(0,5).map(function(h){
        var data = [];
        try{ data = Array.from(new Uint8Array(h.address.sub(32).readByteArray(128))); } catch(e){}
        return {addr: h.address.toString(), data: data};
    })};
}

// 3. 找 SingleUserForwardMessageWindow 相关的方法（UI 层）
var sfmw_pattern = '53 69 6e 67 6c 65 55 73 65 72 46 6f 72 77 61 72 64';  // SingleUserForward
var sfmw_hits = Memory.scanSync(wxBase, wxSize, sfmw_pattern);
results.sfmw = {count: sfmw_hits.length, entries: sfmw_hits.slice(0,3).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(32).readByteArray(256))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 4. 找 "forward_scene" 字符串（前向转发场景参数）
var scene_pattern = '66 6f 72 77 61 72 64 5f 73 63 65 6e 65';  // "forward_scene"
var scene_hits = Memory.scanSync(wxBase, wxSize, scene_pattern);
results.forward_scene = {count: scene_hits.length, entries: scene_hits.slice(0,3).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(32).readByteArray(256))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 5. 找 "SyncFWMessageTask" RTTI 的 vtable 指针
var rtti_name_pattern = '2e 3f 41 56 53 79 6e 63 46 57 4d 65 73 73 61 67 65 54 61 73 6b 40 6c 6f 67 69 63 40 77 65 77 6f 72 6b 40 40';
var rtti_hits = Memory.scanSync(wxBase, wxSize, rtti_name_pattern);
results.syncfw_rtti = {count: rtti_hits.length, entries: rtti_hits.slice(0,3).map(function(h){
    var data = [];
    // vtable 通常在 RTTI 的前面
    try{ data = Array.from(new Uint8Array(h.address.sub(32).readByteArray(128))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 6. 找 "kHasClickMigrateChatRecordViewKey" 字符串（在 SyncFWMessageTask 源码中紧跟 begin）
var migrate_pattern = '6b 48 61 73 43 6c 69 63 6b 4d 69 67 72 61 74 65';  // kHasClick...
var migrate_hits = Memory.scanSync(wxBase, wxSize, migrate_pattern);
results.migrate_key = {count: migrate_hits.length, entries: migrate_hits.slice(0,3).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(64).readByteArray(512))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

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

print(f'\n[=== SyncFWMessageTask 分析 ===]')

# 1. begin 字符串
begin_str = result_data.get('begin_str', {})
print(f'\n"[SyncFWMessageTask] begin": {begin_str.get("count",0)} 处')
for a in begin_str.get('addrs', []):
    print(f'  str@{a}')

# 2. 引用
begin_refs = result_data.get('begin_refs', {})
print(f'\n引用 begin 字符串的代码: {begin_refs.get("count",0)} 处')
for entry in begin_refs.get('entries', [])[:3]:
    addr = entry['addr']
    bs = bytes(entry.get('data', []))
    print(f'\n  ref@{addr} (这个地址附近就是 SyncFWMessageTask::Begin 函数):')
    # 打印 hex 用于反汇编分析
    hex_bytes = ' '.join(f'{b:02x}' for b in bs[:64])
    print(f'    hex: {hex_bytes}')

# 3. RTTI
syncfw_rtti = result_data.get('syncfw_rtti', {})
print(f'\nSyncFWMessageTask RTTI: {syncfw_rtti.get("count",0)} 处')
for entry in syncfw_rtti.get('entries', [])[:2]:
    addr = entry['addr']
    bs = bytes(entry.get('data', []))
    hex_bytes = ' '.join(f'{b:02x}' for b in bs[:64])
    print(f'  rtti@{addr}: {hex_bytes}')

# 4. forward_scene
fwd_scene = result_data.get('forward_scene', {})
print(f'\n"forward_scene": {fwd_scene.get("count",0)} 处')
for entry in fwd_scene.get('entries', [])[:3]:
    addr = entry['addr']
    bs = bytes(entry.get('data', []))
    strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]
    print(f'\n  @{addr}:')
    for off, s in strs[:6]:
        print(f'    +{off}: {s[:100]}')

# 5. sfmw - SingleUserForwardMessageWindow
sfmw = result_data.get('sfmw', {})
print(f'\n\nSingleUserForwardMessageWindow: {sfmw.get("count",0)} 处')
for entry in sfmw.get('entries', [])[:2]:
    addr = entry['addr']
    bs = bytes(entry.get('data', []))
    strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]
    print(f'\n  @{addr}:')
    for off, s in strs[:5]:
        print(f'    +{off}: {s[:100]}')

# 6. kHasClickMigrateChatRecordViewKey
migrate = result_data.get('migrate_key', {})
print(f'\n"kHasClick..." (SyncFWMessageTask 附近): {migrate.get("count",0)} 处')
for entry in migrate.get('entries', [])[:3]:
    addr = entry['addr']
    bs = bytes(entry.get('data', []))
    strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]
    print(f'\n  @{addr}:')
    for off, s in strs[:5]:
        print(f'    +{off}: {s[:100]}')

os._exit(0)
