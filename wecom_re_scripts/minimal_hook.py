# minimal_hook.py - 最简 hook：确认 0x4493c0/449f60/44aaa0 是否触发
# onEnter 中只做最少操作

import frida, subprocess, sys, os, time, threading, json
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

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

var captures = [];
var fwdActive = false;

// CGI_ITER - 标记转发
var CGI_ITER = wxBase.add(0x390B39);
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            try{
                var b = args[1].readByteArray(4);
                var bArr = new Uint8Array(b);
                if(bArr[0]==0x01 && bArr[1]==0x00 && bArr[2]==0x41 && bArr[3]==0x79){
                    fwdActive = true;
                    captures.push({t:'cgi', at: Date.now()});
                    send({t:'cgi_hit'});
                }
            } catch(e){}
        }
    });
    send({t:'ok', fn:'CGI_ITER'});
} catch(e){ send({t:'fail', fn:'CGI_ITER', m:e.message}); }

// FN 0x4493c0 - 最简 onEnter
var FN1 = wxBase.add(0x4493c0);
try{
    Interceptor.attach(FN1, {
        onEnter: function(args){
            captures.push({t:'fn1', ecx:this.context.ecx.toString()});
            send({t:'fn_hit', fn:'0x4493c0', active:fwdActive});
        }
    });
    send({t:'ok', fn:'0x4493c0'});
} catch(e){ send({t:'fail', fn:'0x4493c0', m:e.message}); }

// FN 0x449f60
var FN2 = wxBase.add(0x449f60);
try{
    Interceptor.attach(FN2, {
        onEnter: function(args){
            captures.push({t:'fn2', ecx:this.context.ecx.toString()});
            send({t:'fn_hit', fn:'0x449f60', active:fwdActive});
        }
    });
    send({t:'ok', fn:'0x449f60'});
} catch(e){ send({t:'fail', fn:'0x449f60', m:e.message}); }

// FN 0x44aaa0
var FN3 = wxBase.add(0x44aaa0);
try{
    Interceptor.attach(FN3, {
        onEnter: function(args){
            captures.push({t:'fn3', ecx:this.context.ecx.toString()});
            send({t:'fn_hit', fn:'0x44aaa0', active:fwdActive});
        }
    });
    send({t:'ok', fn:'0x44aaa0'});
} catch(e){ send({t:'fail', fn:'0x44aaa0', m:e.message}); }

// 也试一下 +0x4 和 +0x8 偏移（可能入口是不同 prologue）
// 有时 MSVC 用 sub esp,xxx 作为入口而不是 push ebp
var FN1b = wxBase.add(0x4493c4);  // +4
try{
    Interceptor.attach(FN1b, {
        onEnter: function(args){
            captures.push({t:'fn1b'});
            send({t:'fn_hit', fn:'0x4493c4'});
        }
    });
    send({t:'ok', fn:'0x4493c4'});
} catch(e){}

recv('dump', function(_){
    send({t:'dump', caps: captures.slice(-100)});
});
send({t:'ready'});
"""

hit_event = threading.Event()
dump_event = threading.Event()
fn_hits = []
cgi_hits = []

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'cgi_hit':
        print('  ★ [CGI HIT] 01004179')
        cgi_hits.append(1)
        hit_event.set()
    elif t == 'fn_hit':
        active = p.get('active', False)
        fn = p.get('fn', '?')
        print(f'  ★ [FN HIT] {fn} (fwdActive={active})')
        fn_hits.append(fn)
        hit_event.set()
    elif t == 'ready': print('[+] READY!')
    elif t == 'dump':
        print(f'  dump: {len(p.get("caps",[]))} items')

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print()
print('='*60)
print('★★★ 请转发消息！★★★')
print('='*60)
print()

hit_event.wait(timeout=120)
print(f'[+] cgi_hits={len(cgi_hits)}, fn_hits={fn_hits}')
time.sleep(3)
sc.post({'type': 'dump'})

if len(fn_hits) == 0 and len(cgi_hits) > 0:
    print('\n[!!!] CGI 触发但 FN HOOKS 未触发！')
    print('  → 函数 0x4493c0/449f60/44aaa0 不在调用链上，或地址错误')
    print('  → 可能这些地址不是独立函数，而是 thunk/lambda')
    print('  → 下一步：hook CGI_ITER 时用 onLeave 捕获栈上的参数')

os._exit(0)
