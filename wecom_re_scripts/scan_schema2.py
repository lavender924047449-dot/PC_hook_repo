# scan_schema2.py: 深度扫描 ForwardMessageReq / SingleForwardMsgItem 的完整 proto 结构

import frida, subprocess, sys, os, time, json, re
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

TARGET_STRINGS = [
    'ForwardMessageReq',
    'SingleForwardMsgItem',
    'fwid',
    'msgid',
    'msg_sendtime',
    'ForwardMessageRsp',
    'GetWXMultiForwardMsgReq',
    'DecodeWXForwardMessage',
    'BuildScreenMessageFromContext',
    'SerializeToString',
    'external_userid',
    'corp_id',
    'receiver',
    'to_username',
    'from_username',
    'new_chat_info',
    'combineid',
    'multi_forward',
]

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
});
var wxBase = wx.base;
var wxSize = wx.size;
send({t:'info', base: wxBase.toString()});

var targets = """ + json.dumps(TARGET_STRINGS) + r""";
var results = {};

for(var ti=0; ti<targets.length; ti++){
    var tstr = targets[ti];
    var pattern = tstr.split('').map(function(c){ return c.charCodeAt(0).toString(16).padStart(2,'0'); }).join(' ');
    try {
        var hits = Memory.scanSync(wxBase, wxSize, pattern);
        var entries = [];
        for(var hi=0; hi<hits.length && hi<5; hi++){
            var addr = hits[hi].address;
            try{
                // 读 256B 前后
                var before = Array.from(new Uint8Array(addr.sub(128).readByteArray(128)));
                var after = Array.from(new Uint8Array(addr.readByteArray(512)));
                entries.push({addr: addr.toString(), before: before, after: after});
            } catch(e){ entries.push({addr: addr.toString()}); }
        }
        results[tstr] = {count: hits.length, entries: entries};
    } catch(e){
        results[tstr] = {count: 0, entries: [], err: e.message};
    }
}

send({t:'scan_result', results: results});
send({t:'done'});
"""

scan_results = {}
done_event = False

def on_message(msg, data):
    global done_event
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  base={p["base"]}')
    elif t == 'scan_result':
        scan_results.update(p.get('results', {}))
        print(f'  scan done: {len(scan_results)} strings scanned')
    elif t == 'done':
        done_event = True

import threading
done = threading.Event()

def on_msg2(msg, data):
    on_message(msg, data)
    if msg.get('type') == 'send' and msg.get('payload', {}).get('t') == 'done':
        done.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg2)
sc.load()
done.wait(timeout=60)
sess.detach()

# ─── 分析 ─────────────────────────────────────────────────────────────────────
print(f'\n[=== 扫描结果 ===]')

for tstr, info in scan_results.items():
    count = info.get('count', 0)
    entries = info.get('entries', [])
    if count == 0: continue
    
    print(f'\n{"="*60}')
    print(f'"{tstr}" ({count} 处):')
    
    for ei, entry in enumerate(entries[:3]):
        before = bytes(entry.get('before', []))
        after = bytes(entry.get('after', []))
        addr = entry.get('addr', '?')
        
        print(f'\n  #{ei} @ {addr}:')
        
        # 找 before 中的 proto 字段名（通常是 snake_case 格式）
        for m in re.finditer(rb'[a-z][a-z0-9_]{2,30}', before):
            s = m.group().decode('ascii')
            if re.match(r'^[a-z][a-z0-9_]+$', s) and len(s) >= 3:
                print(f'    B[-{len(before)-m.start()}]: {s}')
        
        # 打印 after 中所有可读字符串
        pos = 0
        while pos < min(512, len(after)):
            if after[pos] >= 0x20 and after[pos] <= 0x7e:
                start = pos
                while pos < len(after) and after[pos] >= 0x20 and after[pos] <= 0x7e:
                    pos += 1
                s = after[start:pos].decode('ascii','ignore')
                if len(s) >= 4:
                    print(f'    A[+{start}]: {s[:100]}')
            else:
                pos += 1

# 重点：找所有 proto 字段名组合
print(f'\n\n{"="*60}')
print('=== Proto 字段名候选 ===')

field_candidates = set()
for tstr, info in scan_results.items():
    for entry in info.get('entries', []):
        for arr_key in ['before', 'after']:
            bs = bytes(entry.get(arr_key, []))
            # 找 snake_case 字符串
            for m in re.finditer(rb'\b[a-z][a-z0-9_]{2,40}\b', bs):
                s = m.group().decode('ascii')
                if re.match(r'^[a-z][a-z0-9_]{2,}$', s) and '_' in s:
                    field_candidates.add(s)

# 过滤掉常见关键字
exclude = {'for', 'the', 'and', 'not', 'this', 'that', 'from', 'with', 'has_', 'get_', 'set_'}
print('\nField name candidates (snake_case):')
for f in sorted(field_candidates):
    if not any(e in f for e in ['assert', 'debug', 'error', 'warn', 'true', 'false', 'null']):
        print(f'  {f}')

ts = f'schema_{int(time.time())}'
out = OUT_DIR / f'{ts}.json'
out.write_text(json.dumps(scan_results, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

os._exit(0)
