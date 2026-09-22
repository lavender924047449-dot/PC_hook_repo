# read_call_chain.py
# 1. 验证 return addr 0x4493f2 处确实有 CALL 0x390B39 指令
# 2. 从 0x4493ed 向前扫真正函数入口（包括 SEH prologue）
# 3. 读出函数入口代码，理解参数布局

import frida, subprocess, sys, os, time, json, struct
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

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
send({t:'info', base: wxBase.toString()});

function safeRead(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

// ── 1. 验证 0x4493ed 处的 CALL 指令 ──────────────────────────────────────────
// return addr = WXWork+0x4493f2，call instr 应在 WXWork+0x4493ed (5 bytes E8 xx xx xx xx)
var callAddr = wxBase.add(0x4493ed);
var callBytes = safeRead(callAddr, 5);
send({t:'call_check', addr: callAddr.toString(), bytes: callBytes});

// ── 2. 读 0x4493c0 到 0x4493ed 的代码（找真实入口） ──────────────────────────
// 从 return_addr 往前读 512B，找所有可能的函数入口 pattern
var scanStart = wxBase.add(0x4493c0 - 200);
var scanCode = safeRead(scanStart, 700);
send({t:'code_scan', start: scanStart.toString(), code: scanCode});

// ── 3. 同样对 0x449fa7 和 0x44aacd 验证 ─────────────────────────────────────
var fn2_scan = safeRead(wxBase.add(0x449f60 - 200), 500);
send({t:'code_scan2', start: wxBase.add(0x449f60-200).toString(), code: fn2_scan});

var fn3_scan = safeRead(wxBase.add(0x44aaa0 - 200), 500);
send({t:'code_scan3', start: wxBase.add(0x44aaa0-200).toString(), code: fn3_scan});

// ── 4. CGI_ITER 的调用者通过 onEnter 读栈 ────────────────────────────────────
// 从栈上直接读 return address 及前后的代码上下文
var captures = [];
var CGI_ITER = wxBase.add(0x390B39);
var cgiHit = false;
try{
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args){
            var b4 = null;
            try{ b4 = new Uint8Array(args[1].readByteArray(4)); } catch(e){}
            if(!b4 || !(b4[0]==0x01 && b4[1]==0x00 && b4[2]==0x41 && b4[3]==0x79)) return;
            if(cgiHit) return; // 只捕一次
            cgiHit = true;
            
            // 读当前栈帧
            var sp = this.context.esp >>> 0;
            var stackData = safeRead(sp, 256);
            // 第一个 return address 在 [esp]
            // 读它前后的代码
            var retAddr = null;
            if(stackData){
                retAddr = (stackData[0])|(stackData[1]<<8)|(stackData[2]<<16)|(stackData[3]<<24);
                retAddr = retAddr >>> 0;
            }
            var retCode = null;
            if(retAddr > 0x10000 && retAddr < 0x7FFFFFFF){
                retCode = safeRead(retAddr - 50, 100);
            }
            
            // 读 EBP 链（frame pointers）
            var ebp = this.context.ebp >>> 0;
            var frames = [];
            for(var i=0; i<10; i++){
                if(ebp < 0x10000 || ebp > 0x7FFFFFFF) break;
                var frame = safeRead(ebp, 8);
                if(!frame) break;
                var nextEbp = (frame[0])|(frame[1]<<8)|(frame[2]<<16)|(frame[3]<<24);
                var ra = (frame[4])|(frame[5]<<8)|(frame[6]<<16)|(frame[7]<<24);
                nextEbp = nextEbp >>> 0; ra = ra >>> 0;
                frames.push({ebp:'0x'+ebp.toString(16), ret:'0x'+ra.toString(16)});
                ebp = nextEbp;
            }
            
            captures.push({
                sp:'0x'+sp.toString(16),
                stackData: stackData,
                retAddr:'0x'+(retAddr||0).toString(16),
                retCode: retCode,
                frames: frames
            });
            send({t:'cgi_hit', sp:'0x'+sp.toString(16), retAddr:'0x'+(retAddr||0).toString(16), 
                frames: frames.map(function(f){ return f.ret; })});
        }
    });
    send({t:'hook_ok', fn:'CGI_ITER'});
} catch(e){ send({t:'hook_fail', fn:'CGI_ITER', m:e.message}); }

recv('dump', function(_){
    send({t:'dump', caps: captures});
});
send({t:'ready'});
"""

captures = []
dump_event = None

def on_message(msg, data):
    global captures
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'hook_ok': print(f'  [OK] {p["fn"]}')
    elif t == 'hook_fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'ready': print('[+] READY (静态分析完成)')
    elif t == 'call_check':
        bs = bytes(p.get('bytes') or [])
        print(f'\n  CALL check @ {p["addr"]}:')
        print(f'    bytes: {bs.hex()} = {" ".join(f"{b:02x}" for b in bs)}')
        if bs and bs[0] == 0xe8:
            rel = struct.unpack_from('<i', bs, 1)[0]
            # next IP after call = p["addr"] + 5
            # actual CGI_ITER_ADDR should be the target
            print(f'    E8 relative={rel:#x} ({rel})')
    elif t == 'code_scan':
        bs = bytes(p.get('code') or [])
        start_str = p.get('start','?')
        print(f'\n  Code scan from {start_str} ({len(bs)}B):')
        # 找所有函数入口模式
        patterns = [
            (b'\x55\x8b\xec', 'PUSH EBP / MOV EBP ESP'),
            (b'\x6a\xff\x68', 'PUSH -1 / PUSH (SEH)'),
            (b'\x53\x55\x8b\xec', 'PUSH EBX / PUSH EBP'),
            (b'\x56\x57\x55\x8b\xec', 'PUSH ESI/EDI/EBP'),
            (b'\x83\xec', 'SUB ESP,xx'),
        ]
        found = []
        for i in range(len(bs)):
            for pat, desc in patterns:
                if bs[i:i+len(pat)] == pat:
                    found.append((i, desc, bs[i:i+10].hex()))
        
        # 打印找到的模式
        for off, desc, hx in found:
            try:
                abs_addr = int(start_str, 16) + off
                from_ret = 0x4493ed - abs_addr + 0x2d0000
                print(f'    @offset+{off} ({abs_addr:#010x} = WXWork+{abs_addr-0x2d0000:#x}) [{desc}] {hx[:20]}')
                print(f'      → 距 return_addr(0x4493ed) = {from_ret:#x}')
            except: print(f'    @offset+{off} [{desc}] {hx[:20]}')
        
    elif t == 'code_scan2':
        bs = bytes(p.get('code') or [])
        start_str = p.get('start','?')
        print(f'\n  Code scan2 (fn2) from {start_str} ({len(bs)}B):')
        for i in range(len(bs)):
            if bs[i:i+3] == b'\x55\x8b\xec' or bs[i:i+3] == b'\x6a\xff\x68':
                try:
                    abs_addr = int(start_str, 16) + i
                    print(f'    @+{i} ({abs_addr:#010x} = WXWork+{abs_addr-0x2d0000:#x}) {bs[i:i+6].hex()}')
                except: print(f'    @+{i} {bs[i:i+6].hex()}')

    elif t == 'code_scan3':
        bs = bytes(p.get('code') or [])
        start_str = p.get('start','?')
        print(f'\n  Code scan3 (fn3) from {start_str} ({len(bs)}B):')
        for i in range(len(bs)):
            if bs[i:i+3] == b'\x55\x8b\xec' or bs[i:i+3] == b'\x6a\xff\x68':
                try:
                    abs_addr = int(start_str, 16) + i
                    print(f'    @+{i} ({abs_addr:#010x} = WXWork+{abs_addr-0x2d0000:#x}) {bs[i:i+6].hex()}')
                except: print(f'    @+{i} {bs[i:i+6].hex()}')

    elif t == 'cgi_hit':
        print(f'\n  ★ CGI HIT!')
        print(f'    sp={p["sp"]} retAddr={p["retAddr"]}')
        print(f'    EBP chain returns: {p.get("frames",[])}')

    elif t == 'dump':
        captures.extend(p.get('caps',[]))
        if dump_event: dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(3)

import threading
dump_event = threading.Event()
hit_event = threading.Event()

def on_msg2(msg, data):
    if msg.get('type') == 'send':
        p = msg['payload']
        if p.get('t') == 'cgi_hit': hit_event.set()
    on_message(msg, data)

sc.off('message', on_message)
sc.on('message', on_msg2)

print()
print('='*60)
print('★★★ 请转发消息！(120s)★★★')
print('='*60)

hit_event.wait(timeout=120)
time.sleep(2)
sc.post({'type':'dump'})
dump_event.wait(timeout=10)

# 分析
if captures:
    cap = captures[0]
    print(f'\n[=== 栈分析 ===]')
    print(f'  SP={cap.get("sp")} retAddr={cap.get("retAddr")}')
    print('  EBP chain:')
    for f in cap.get('frames',[]):
        ret = f.get('ret','?')
        try:
            a = int(ret, 16)
            if 0x2d0000 <= a < 0x2d0000 + 0x20000000:
                print(f'    ret={ret} (WXWork+{a-0x2d0000:#x})')
            else:
                print(f'    ret={ret}')
        except: print(f'    ret={ret}')
    
    # 保存
    out = OUT_DIR / f'call_chain_{int(time.time())}.json'
    out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'\n[+] 保存: {out}')

os._exit(0)
