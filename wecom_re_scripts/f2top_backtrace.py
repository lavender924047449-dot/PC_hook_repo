# f2top_backtrace.py - hook f2_top（当前已知地址），在转发时捕获调用栈
# f2_top 是压缩/编码层，转发 CGI 01004179 必经此函数
# 同时尝试用新 RVA（0x430B39 = 旧0x390B39 + 0xA0000 shift）找 CGI_ITER

import frida, subprocess, sys, os, time, threading, json, struct, re
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
send({t:'info', base: wxBase.toString(), size:'0x'+wx.size.toString(16)});

function safeRead(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

// f2_top 当前已知 RVA
var F2_TOP_RVA = 0x96DE58A;
var f2top = wxBase.add(F2_TOP_RVA);
send({t:'addr', fn:'f2_top', abs: f2top.toString()});

// 尝试旧 RVA + 0xA0000 的 CGI_ITER
var CGI_ITER_RVA_SHIFTED = 0x390B39 + 0xA0000;  // = 0x430B39
var cgi_iter_shifted = wxBase.add(CGI_ITER_RVA_SHIFTED);
send({t:'addr', fn:'CGI_ITER_shifted', abs: cgi_iter_shifted.toString()});

var captures = [];
var captureCount = 0;
var started = Date.now();

// hook f2_top
try{
    Interceptor.attach(f2top, {
        onEnter: function(args){
            var elapsed = Date.now() - started;
            // args[2] 是 log prefix (旧分析)，但也尝试 args[0-3]
            // 检查任意 arg 是否包含 01004179
            var found_fwd = false;
            var arg_strs = [];
            
            for(var i=0; i<6; i++){
                try{
                    var v = args[i].toInt32() >>> 0;
                    arg_strs.push('0x'+v.toString(16));
                    
                    // 尝试读4字节
                    var b4 = safeRead(args[i], 4);
                    if(b4 && b4[0]==0x01 && b4[1]==0x00 && b4[2]==0x41 && b4[3]==0x79){
                        found_fwd = true;
                    }
                    
                    // 读16字节看是否包含 01 00 41 79
                    var b16 = safeRead(args[i], 16);
                    if(b16){
                        for(var j=0; j<13; j++){
                            if(b16[j]==0x01 && b16[j+1]==0x00 && b16[j+2]==0x41 && b16[j+3]==0x79){
                                found_fwd = true; break;
                            }
                        }
                    }
                } catch(e){}
            }
            
            if(found_fwd){
                captureCount++;
                var bt = [];
                try{
                    bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .slice(0, 25)
                        .map(function(a){ return '0x'+a.toString(16); });
                } catch(e){ bt = ['bt_err: '+e.message]; }
                
                captures.push({
                    n: captureCount,
                    elapsed: elapsed,
                    args: arg_strs,
                    backtrace: bt
                });
                send({t:'hit_f2', n: captureCount, bt_len: bt.length});
            }
        }
    });
    send({t:'ok', fn:'f2_top hook'});
} catch(e){ send({t:'err', m:'f2_top: '+e.message}); }

// 同时 hook CGI_ITER（shifted）
try{
    Interceptor.attach(cgi_iter_shifted, {
        onEnter: function(args){
            var b4 = safeRead(args[0], 4);
            if(!b4) return;
            var compact = b4[0].toString(16).padStart(2,'0') +
                          b4[1].toString(16).padStart(2,'0') +
                          b4[2].toString(16).padStart(2,'0') +
                          b4[3].toString(16).padStart(2,'0');
            send({t:'cgi_iter_hit', compact: compact, args0: args[0].toString()});
        }
    });
    send({t:'ok', fn:'CGI_ITER_shifted hook'});
} catch(e){ send({t:'warn', m:'CGI_ITER_shifted: '+e.message}); }

recv('dump', function(_){
    send({t:'dump_result', caps: captures});
});

send({t:'ready'});
"""

captures = []
dump_event = threading.Event()
hit_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'info': print(f'  wxBase={p["base"]}  size={p["size"]}')
    elif t == 'addr': print(f'  {p["fn"]} abs={p["abs"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'warn': print(f'  [WARN] {p["m"]}')
    elif t == 'err': print(f'  [ERR] {p["m"]}')
    elif t == 'ready': print('[+] HOOKS READY — 请转发消息！')
    elif t == 'hit_f2':
        print(f'  ★ [F2 FWD HIT] #{p["n"]} bt={p["bt_len"]}f')
        hit_event.set()
    elif t == 'cgi_iter_hit':
        print(f'  [CGI_ITER] compact={p["compact"]}')
    elif t == 'dump_result':
        captures.extend(p.get('caps', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print()
print('='*60)
print('★★★ 请在企微转发消息！★★★')
print('='*60)
print()

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 超时 300s，无 ForwardMessage f2 hit')
    # 不退出，dump 任何已有捕获
else:
    print('[+] 检测到 FWD Hit！等 3s...')
    time.sleep(3)

sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

print(f'\n[=== 分析 {len(captures)} 次 f2_top FWD 捕获 ===]')

for ci, cap in enumerate(captures):
    print(f'\nCap #{ci}: args={cap.get("args")[:4]}')
    print('  调用栈:')
    for fi, frame in enumerate(cap.get('backtrace', [])):
        try:
            a = int(frame, 16)
            if 0x2d0000 <= a < 0x2d0000 + 0x20000000:
                rva = a - 0x2d0000
                print(f'    #{fi}: {frame} (WXWork+0x{rva:x})')
            else:
                print(f'    #{fi}: {frame}')
        except:
            print(f'    #{fi}: {frame}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'f2bt_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
