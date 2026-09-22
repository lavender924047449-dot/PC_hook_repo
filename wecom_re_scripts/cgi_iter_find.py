# cgi_iter_find.py - 多种方式找 CGI_ITER，并在转发时获取调用栈
# 1. 尝试原始 RVA 0x390B39（读 args[1]）
# 2. 扫描内存中 01 00 41 79 附近的函数指针
# 3. 捕获转发调用栈

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
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
send({t:'info', base: wxBase.toString(), size:'0x'+wx.size.toString(16)});

function safeRead(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}
function safeHex(p, n){ 
    var b = safeRead(p, n);
    if(!b) return null;
    return b.map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
}

var captures = [];
var hitCount = 0;
var cgiIterFired = false;

// ── 方案A: 原始 RVA 0x390B39 ─────────────────────────────────────────────────
var CGI_A = wxBase.add(0x390B39);
send({t:'try', label:'CGI_A(0x390B39)', abs: CGI_A.toString()});
try{
    Interceptor.attach(CGI_A, {
        onEnter: function(args){
            try{
                var b4 = safeRead(args[1], 4);
                if(!b4) { send({t:'cgi_fire', src:'A', compact:'null_a1'}); return; }
                var compact = b4.map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
                send({t:'cgi_fire', src:'A', compact: compact});
                
                if(compact === '01004179'){
                    hitCount++;
                    var bt = [];
                    try{
                        bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .slice(0,20).map(function(a){ return '0x'+a.toString(16); });
                    } catch(e){ bt=['bt_err']; }
                    captures.push({src:'A', compact:compact, backtrace:bt, 
                        a1: safeRead(args[1], 1024)});
                    send({t:'fwd_hit', src:'A', n:hitCount, bt:bt.length});
                }
            } catch(e){ send({t:'cgi_err', src:'A', m:e.message}); }
        }
    });
    send({t:'hook_ok', label:'CGI_A'});
} catch(e){ send({t:'hook_fail', label:'CGI_A', m:e.message}); }

// ── 方案B: RVA 0x390B39 + 0xA0000 (shift假设) ────────────────────────────────
var CGI_B = wxBase.add(0x430B39);
send({t:'try', label:'CGI_B(0x430B39)', abs: CGI_B.toString()});
try{
    Interceptor.attach(CGI_B, {
        onEnter: function(args){
            try{
                var b4 = safeRead(args[1], 4);
                var compact = b4 ? b4.map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('') : 'null';
                send({t:'cgi_fire', src:'B', compact: compact});
                if(compact === '01004179'){
                    hitCount++;
                    var bt = [];
                    try{ bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .slice(0,20).map(function(a){ return '0x'+a.toString(16); }); } catch(e){}
                    captures.push({src:'B', compact:compact, backtrace:bt, a1:safeRead(args[1],1024)});
                    send({t:'fwd_hit', src:'B', n:hitCount});
                }
            } catch(e){}
        }
    });
    send({t:'hook_ok', label:'CGI_B'});
} catch(e){ send({t:'hook_fail', label:'CGI_B', m:e.message}); }

// ── 方案C: 扫描内存找 '01 00 41 79' pattern 在只读/数据段 ─────────────────────
// 目的：找到 CGI 分发表，间接找 CGI_ITER 位置
var fwdPatHits = Memory.scanSync(wxBase, wx.size, '01 00 41 79');
send({t:'fwd_pat_hits', n: fwdPatHits.length, 
    addrs: fwdPatHits.slice(0,10).map(function(h){ return h.address.toString(); })});

// ── 方案D: 挂 f2_top，不过滤，捕获所有 args ──────────────────────────────────
var F2_TOP = wxBase.add(0x96DE58A);
send({t:'try', label:'F2_TOP', abs: F2_TOP.toString()});
var f2count = 0;
try{
    Interceptor.attach(F2_TOP, {
        onEnter: function(args){
            f2count++;
            // 每 100 次报告一次
            if(f2count % 100 === 0){ send({t:'f2_count', n:f2count}); }
        }
    });
    send({t:'hook_ok', label:'F2_TOP'});
} catch(e){ send({t:'hook_fail', label:'F2_TOP', m:e.message}); }

recv('dump', function(_){
    send({t:'dump', caps: captures, f2_total: f2count});
});

send({t:'ready'});
"""

captures = []
dump_event = threading.Event()
hit_event = threading.Event()
cgi_fires = []

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  wxBase={p["base"]} size={p["size"]}')
    elif t == 'try': print(f'  trying {p["label"]} @ {p["abs"]}')
    elif t == 'hook_ok': print(f'  [OK] {p["label"]}')
    elif t == 'hook_fail': print(f'  [FAIL] {p["label"]}: {p["m"]}')
    elif t == 'cgi_fire':
        compact = p.get('compact','?')
        cgi_fires.append({'src': p['src'], 'compact': compact})
        if len(cgi_fires) <= 10:  # 只打印前10个
            print(f'  [CGI/{p["src"]}] {compact}')
    elif t == 'cgi_err': print(f'  [CGI_ERR/{p.get("src")}] {p.get("m")}')
    elif t == 'fwd_hit':
        print(f'  ★★★ [FWD HIT] src={p["src"]} n={p["n"]}')
        hit_event.set()
    elif t == 'fwd_pat_hits':
        print(f'  [01004179 pattern hits] {p["n"]} 处:')
        for a in p.get('addrs',[]): print(f'    {a}')
    elif t == 'f2_count': print(f'  f2_top call count: {p["n"]}')
    elif t == 'dump':
        captures.extend(p.get('caps',[]))
        print(f'  [dump] f2_total={p.get("f2_total",0)}, captures={len(captures)}')
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(3)

print()
print('='*60)
print('★★★ 请在企微转发消息！★★★  (120s 超时)')
print('='*60)
print()
print('（若 CGI_A/B 触发，会看到 [CGI/A] 或 [CGI/B] 打印）')
print()

got = hit_event.wait(timeout=120)

if not got:
    print(f'[!] 120s 内无 ForwardMessage hit')
    print(f'    CGI fires 总计: {len(cgi_fires)}')
    print(f'    各 compact 列表:')
    compacts = {}
    for f in cgi_fires:
        k = f'{f["src"]}:{f["compact"]}'
        compacts[k] = compacts.get(k, 0) + 1
    for k, v in sorted(compacts.items()): print(f'      {k}: {v}')
else:
    print('[+] FWD HIT! 等 3s...')
    time.sleep(3)

sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

# ─── 分析捕获 ────────────────────────────────────────────────────────────────
if captures:
    print(f'\n[=== 捕获 {len(captures)} 条 FWD ===]')
    for ci, cap in enumerate(captures):
        print(f'\nCap #{ci} src={cap.get("src")}:')
        print('  调用栈:')
        for fi, frame in enumerate(cap.get('backtrace',[])):
            try:
                a = int(frame, 16)
                if 0x2d0000 <= a < 0x2d0000 + 0x20000000:
                    print(f'    #{fi}: {frame} (WXWork+0x{a-0x2d0000:x})')
                else:
                    print(f'    #{fi}: {frame}')
            except: print(f'    #{fi}: {frame}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'cgi_iter_find_{ts}.json'
out.write_text(json.dumps({'captures':captures,'cgi_fires':cgi_fires[:100]}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
