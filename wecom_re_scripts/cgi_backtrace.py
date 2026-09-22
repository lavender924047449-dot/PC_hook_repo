# cgi_backtrace.py: 当 CGI 01004179（ForwardMessage）触发时，捕获调用栈
# 目标：找出谁调用了这个 CGI，从而定位真正的转发入口函数
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
send({t:'info', base: wxBase.toString()});

function safeRead(p, n){
    try{ return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e){ return null; }
}

// CGI_ITER: f2_top 以读到 CGI pattern 为标志
// 我们直接在 CGI 发送函数处挂钩：搜索 call stack
// 策略: hook f2_top (已知 RVA = 0x96DE58A)，当 args[2] 包含 "01004179" 时捕获

// 已知 f2_top 绝对地址（base=0x2d0000, RVA=0x96DE58A）
var F2_TOP_ABS = wxBase.add(0x96DE58A);
send({t:'f2_top_addr', addr: F2_TOP_ABS.toString()});

// 同时 hook 另一个候选: CGI_ITER RVA = 0x390A30（从过去分析）
var CGI_ITER_ABS = wxBase.add(0x390A30);
send({t:'cgi_iter_addr', addr: CGI_ITER_ABS.toString()});

var captures = [];
var captureCount = 0;
var dump_event = false;

// CGI_ITER hook
try{
    Interceptor.attach(CGI_ITER_ABS, {
        onEnter: function(args){
            // args[0] 通常是 compact (CGI 模式标记)
            var a0 = args[0] ? args[0].toInt32() : 0;
            
            // 01004179 = 0x01004179 = 16794969 decimal
            // little-endian compact 也可能是 byte-by-byte
            var a0_be = ((a0 >>> 24) & 0xff) | 
                        (((a0 >>> 16) & 0xff) << 8) | 
                        (((a0 >>> 8) & 0xff) << 16) | 
                        ((a0 & 0xff) << 24);
            
            // 也检查 args[0] 直接读取 4 字节
            var bytes4 = safeRead(args[0], 4);
            var compact = bytes4 ? 
                (bytes4[0].toString(16).padStart(2,'0') + 
                 bytes4[1].toString(16).padStart(2,'0') +
                 bytes4[2].toString(16).padStart(2,'0') +
                 bytes4[3].toString(16).padStart(2,'0')) : 'null';
            
            if (compact === '01004179') {
                captureCount++;
                // 获取调用栈
                var bt = [];
                try{
                    bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .slice(0, 20)
                        .map(function(a){ return '0x' + a.toString(16); });
                } catch(e){ bt = ['bt_err: ' + e.message]; }
                
                // 读 args[0..3]
                var a = [];
                for(var i=0; i<4; i++){
                    try{ a.push(args[i].toString()); }
                    catch(e){ a.push('?'); }
                }
                
                // 读 args[1] 的前 1024 字节
                var a1_data = safeRead(args[1], 1024);
                
                captures.push({
                    n: captureCount,
                    args: a,
                    backtrace: bt,
                    a1: a1_data
                });
                send({t:'hit', n: captureCount, compact: compact, bt_depth: bt.length});
            }
        }
    });
    send({t:'ok', hook:'CGI_ITER'});
} catch(e){ send({t:'err', m:'CGI_ITER: ' + e.message}); }

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
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'f2_top_addr': print(f'  f2_top abs={p["addr"]}')
    elif t == 'cgi_iter_addr': print(f'  CGI_ITER abs={p["addr"]}')
    elif t == 'ok': print(f'  [OK] {p["hook"]}')
    elif t == 'err': print(f'  [ERR] {p["m"]}')
    elif t == 'ready': print('[+] HOOKS READY — 请转发消息！')
    elif t == 'hit':
        print(f'  ★ [CGI HIT] #{p["n"]} compact={p["compact"]} bt={p["bt_depth"]}f')
        hit_event.set()
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
    print('[!] 超时 300s 无 CGI Hit，退出')
    os._exit(1)

print('[+] 检测到 Hit，再等 5s...')
time.sleep(5)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ───────────────────────────────────────────────────────────────────

def sym_hint(addr_str, wx_base, wx_size):
    """简单的符号提示：RVA"""
    try:
        a = int(addr_str, 16)
        if wx_base <= a < wx_base + wx_size:
            return f'WXWork+0x{a - wx_base:x}'
        return addr_str
    except:
        return addr_str

def find_strings(bs, minlen=5):
    return [(m.start(), m.group().decode('ascii','ignore'))
            for m in re.finditer(rb'[\x20-\x7e]{' + str(minlen).encode() + rb',}', bs)]

print(f'\n[=== 分析 {len(captures)} 次 CGI 01004179 捕获 ===]')

for ci, cap in enumerate(captures):
    print(f'\n{"="*60}')
    print(f'Cap #{ci}: args={cap.get("args")}')
    
    print('\n  [调用栈]:')
    for fi, frame in enumerate(cap.get('backtrace', [])):
        print(f'    #{fi}: {frame}')
    
    a1 = bytes(cap.get('a1') or [])
    if a1:
        print(f'\n  a1 ({len(a1)}B):')
        strs = find_strings(a1)
        u16 = []
        i = 0
        while i < len(a1) - 1:
            if 0x20 <= a1[i] <= 0x7e and a1[i+1] == 0:
                start = i; j = i
                while j+1 < len(a1) and 0x20 <= a1[j] <= 0x7e and a1[j+1] == 0: j += 2
                if (j-start) >= 8: u16.append((start, a1[start:j].decode('utf-16-le','ignore'))); i=j; continue
            i += 1
        for off, s in strs[:6]: print(f'    ascii@{off}: {s[:60]}')
        for off, s in u16[:5]: print(f'    utf16@{off}: {s[:60]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'cgi_bt_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

# 打印调用栈 RVA，方便 IDA 分析
if captures:
    bt = captures[0].get('backtrace', [])
    print('\n[== 调用栈 RVA (base=0x2d0000) ==]')
    for frame in bt:
        try:
            a = int(frame, 16)
            if 0x2d0000 <= a < 0x2d0000 + 0x20000000:
                print(f'  RVA 0x{a - 0x2d0000:x}')
            else:
                print(f'  {frame}')
        except: print(f'  {frame}')

os._exit(0)
