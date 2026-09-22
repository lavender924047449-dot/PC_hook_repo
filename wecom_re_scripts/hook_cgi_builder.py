# hook_cgi_builder.py
# 1. 反汇编 0x09BF3608 附近找函数入口
# 2. Hook 该函数，读取 args（CGI cmd + payload ptr）
# 3. 找到 561 字节明文 payload
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/hook_cgi_builder.py

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
print(f'[+] PID={pid}', flush=True)

# 访问 "before compress" 的指令地址
INSTR_ADDR = 0x09BF3608  # abs
WX_BASE = 0x2D0000

JS = r"""
'use strict';
var INSTR = ptr(0x09BF3608);
var wxBase = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
}).base;

// ─── Step 1: 反汇编指令及其周围，找函数开头 ─────────────────────────────────
var disasm = [];
var cur = INSTR.sub(0x200);  // 向前 512 字节找函数 prologue
// 读这块内存
try {
    var bytes = cur.readByteArray(0x300);
    var arr = Array.from(new Uint8Array(bytes));
    // 找典型 x86 函数 prologue: "55 8b ec" (push ebp / mov ebp, esp)
    // 或 "55 89 e5" 等
    var prologues = [];
    for (var i=0; i<arr.length-2; i++) {
        // push ebp; mov ebp, esp
        if (arr[i] === 0x55 && arr[i+1] === 0x8b && arr[i+2] === 0xec) {
            prologues.push({offset: i, abs: cur.add(i).toString()});
        }
        // push ebp; push edi; push esi; or similar
        if (arr[i] === 0x55 && (arr[i+1] === 0x57 || arr[i+1] === 0x56 || arr[i+1] === 0x53)) {
            prologues.push({offset: i, type: 'push multi', abs: cur.add(i).toString()});
        }
    }
    disasm = prologues;
} catch(e) {
    disasm = [{err: e.message}];
}

send({t:'prologues', count: disasm.length, items: disasm});

// ─── Step 2: 直接挂钩指令地址及其函数，读寄存器 ─────────────────────────────
var captures_instr = [];
var captures_funcs = [];

// 挂钩 INSTR_ADDR
try {
    Interceptor.attach(INSTR, {
        onEnter: function(args) {
            var ctx = this.context;
            captures_instr.push({
                eax: ctx.eax.toString(), ecx: ctx.ecx.toString(),
                edx: ctx.edx.toString(), ebx: ctx.ebx.toString(),
                esp: ctx.esp.toString(), ebp: ctx.ebp.toString(),
                esi: ctx.esi.toString(), edi: ctx.edi.toString()
            });
            if (captures_instr.length === 1) {
                send({t:'instr_hit', regs: captures_instr[0]});
            }
        }
    });
    send({t:'attached_instr', addr: INSTR.toString()});
} catch(e) {
    send({t:'attach_err', addr: INSTR.toString(), msg: e.message});
}

// ─── Step 3: 挂钩 INSTR-0x200 到 INSTR 范围的函数开头 (试多个) ─────────────
var PROBE_OFFSETS = [-0x1e0, -0x1a0, -0x160, -0x120, -0xe0, -0xa0, -0x60, -0x30, -0x20, -0x10];
PROBE_OFFSETS.forEach(function(off) {
    var probeAddr = INSTR.add(off);
    try {
        Interceptor.attach(probeAddr, {
            onEnter: function(args) {
                var ctx = this.context;
                var rec = {
                    probe_addr: probeAddr.toString(),
                    ebp: ctx.ebp.toString(),
                    esp: ctx.esp.toString(),
                    ecx: ctx.ecx.toString(),
                    esi: ctx.esi.toString(),
                    args: []
                };
                for (var j=0; j<6; j++) {
                    try {
                        var av = args[j].toInt32();
                        var s = '';
                        if (av > 0x10000 && av < 0x7fffffff) {
                            try { s = ptr(av).readCString(64) || ''; } catch(e) {}
                        }
                        rec.args.push({v: av.toString(16), s: s});
                    } catch(e) { rec.args.push({v:'?'}); }
                }
                captures_funcs.push(rec);
                if (captures_funcs.length % 5 === 0) {
                    send({t:'func_hits', n: captures_funcs.length});
                }
            }
        });
    } catch(e) {} // 忽略无法挂钩的地址
});

function toHex(p, n) {
    try {
        var b = p.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return ''; }
}

recv('dump', function(_) {
    // 当 instr_hit 时，尝试读 EBP 周围和 ECX/ESI 处的内容
    var extra = {};
    if (captures_instr.length > 0) {
        var r = captures_instr[0];
        // 读 EBP-0x100 到 EBP+0x10 的栈帧
        var ebp = parseInt(r.ebp, 16);
        extra.stack = toHex(ptr(ebp - 0x100), 0x120);
        // 读 ECX 处
        extra.ecx_data = toHex(ptr(parseInt(r.ecx, 16)), 256);
        // 读 ESI 处
        extra.esi_data = toHex(ptr(parseInt(r.esi, 16)), 256);
        // 读 [EBP+8], [EBP+0xC], [EBP+0x10] (函数参数)
        extra.ebp8 = toHex(ptr(ebp + 8), 128);
    }
    send({t:'dump_result',
          instr_hits: captures_instr,
          func_hits: captures_funcs,
          extra: extra});
});

send({t:'ready'});
"""

instr_hits = []
func_hits = []
extra_data = {}
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description','')[:300], flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'ready':
        print('[+] Script ready', flush=True)
    elif t in ('attached_instr', 'attach_err', 'prologues'):
        print('[%s] %s' % (t, str(p)[:200]), flush=True)
    elif t == 'instr_hit':
        regs = p.get('regs', {})
        print('  [INSTR HIT] EBP=%s ECX=%s ESI=%s EDI=%s' % (
            regs.get('ebp'), regs.get('ecx'), regs.get('esi'), regs.get('edi')), flush=True)
    elif t == 'func_hits':
        print('  [func hits] n=%d' % p.get('n'), flush=True)
    elif t == 'dump_result':
        instr_hits.extend(p.get('instr_hits', []))
        func_hits.extend(p.get('func_hits', []))
        extra_data.update(p.get('extra', {}))
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print('\n=== 请在 45 秒内转发消息 ===', flush=True)
time.sleep(45)
sc.post({'type': 'dump'})
dump_event.wait(15)

print(f'\n[+] instr hits: {len(instr_hits)}  func hits: {len(func_hits)}', flush=True)

# 分析
def find_strs(hexdata, min_len=5):
    if not hexdata: return []
    try:
        bs = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    results = []
    s = bs.decode('utf-8', errors='ignore')
    for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s):
        w = m.group().strip()
        if w: results.append(('u8', w))
    s16 = bs.decode('utf-16-le', errors='ignore')
    for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s16):
        w = m.group().strip()
        if w: results.append(('u16', w))
    return results[:10]

if instr_hits:
    print('\n--- INSTR HIT ANALYSIS ---', flush=True)
    r = instr_hits[0]
    print('Registers:', r, flush=True)
    
    print('\nStack ([EBP-0x100:EBP+0x10]):')
    strs = find_strs(extra_data.get('stack',''))
    for enc, s in strs:
        print('  [%s] %r' % (enc, s[:100]), flush=True)
    
    print('\n[EBP+8] (1st arg):')
    strs = find_strs(extra_data.get('ebp8',''))
    for enc, s in strs:
        print('  [%s] %r' % (enc, s[:100]), flush=True)
    
    print('\nECX data:')
    strs = find_strs(extra_data.get('ecx_data',''))
    for enc, s in strs:
        print('  [%s] %r' % (enc, s[:100]), flush=True)

# func hits 分析
if func_hits:
    print('\n--- FUNC PROBE HITS ---', flush=True)
    for h in func_hits[:10]:
        print('  probe@%s:' % h.get('probe_addr'), flush=True)
        for j, a in enumerate(h.get('args',[])):
            if a.get('s'):
                print('    arg[%d]=0x%s str=%r' % (j, a.get('v',''), a.get('s','')[:60]), flush=True)

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / ('cgi_builder_%s.json' % ts)
out.write_text(json.dumps({
    'instr_hits': instr_hits,
    'func_hits': func_hits,
    'extra': extra_data
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}', flush=True)

os._exit(0)
