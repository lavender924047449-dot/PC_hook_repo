# find_fwd_compact.py v2 - 干净版，专门找转发时的 compact
# 只读 args[1]（已确认是 compact 位置），记录所有新 compact
# 转发后 Ctrl+C 停止

import frida, subprocess, sys, os, time, json
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

var seen = {};
var allLog = [];

var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                // 读 args[1] 处的 4 字节（compact）
                var b = new Uint8Array(args[1].readByteArray(4));
                var hex = ('0'+b[0].toString(16)).slice(-2)
                        + ('0'+b[1].toString(16)).slice(-2)
                        + ('0'+b[2].toString(16)).slice(-2)
                        + ('0'+b[3].toString(16)).slice(-2);
                
                var isNew = !seen[hex];
                seen[hex] = (seen[hex]||0) + 1;
                
                // 每次都 push 到 log（用于捕获转发时的完整上下文）
                var entry = {hex:hex, ts:Date.now(), isNew:isNew};
                
                // 如果是新 compact，读一些数据
                if(isNew){
                    var argPtrs = [];
                    for(var i=0;i<6;i++){
                        try{ argPtrs.push('0x'+(args[i].toInt32()>>>0).toString(16)); }
                        catch(e){ argPtrs.push('?'); }
                    }
                    entry.args = argPtrs;
                    // 读 args[3] 的头 256 字节
                    try{
                        entry.arg3_bytes = Array.from(new Uint8Array(args[3].readByteArray(256)));
                    }catch(e){}
                    allLog.push(entry);
                    send({t:'new', hex:hex, args:argPtrs});
                }
            }catch(e){}
        }
    });
    send({t:'ok', fn:'CGI_ITER'});
} catch(e){ send({t:'fail', fn:'CGI_ITER', m:e.message}); }

recv('dump', function(_){ send({t:'dump', log:allLog, seen:seen}); });
send({t:'ready'});
"""

all_log = []
seen_compacts = {}

def on_message(msg, data):
    if msg.get('type') == 'error':
        # 安静处理
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'ready':
        print('[+] HOOKS READY - 请在企微转发消息！')
        print('  （每出现新 compact 就会打印，Ctrl+C 停止）\n')
    elif t == 'new':
        hex_val = p['hex']
        args = p.get('args', [])
        seen_compacts[hex_val] = seen_compacts.get(hex_val, 0) + 1
        print(f'  [NEW COMPACT] {hex_val}  args={args[:4]}')
    elif t == 'dump':
        all_log.extend(p.get('log', []))
        seen_compacts.update(p.get('seen', {}))

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass

print('\n[!] Ctrl+C - dumping...')
import threading
dump_done = threading.Event()
def on_dump(msg, data):
    if msg.get('type') == 'send' and msg['payload'].get('t') == 'dump':
        all_log.extend(msg['payload'].get('log', []))
        seen_compacts.update(msg['payload'].get('seen', {}))
        dump_done.set()
sc.on('message', on_dump)
sc.post({'type': 'dump'})
dump_done.wait(timeout=5)

print('\n所有出现过的 compact:')
for k, v in sorted(seen_compacts.items()):
    marker = '  ← 这个可能是转发！' if k.startswith('010041') else ''
    print(f'  {k}: {v}次{marker}')

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'compact_scan_{ts}.json'
out.write_text(json.dumps({'seen': seen_compacts, 'log': all_log}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
