# hook_fn_prologue.py
# 同时做三件事：
# 1. 挂钩 0x9BF35A0（含 "before compress" 的函数 prologue）
# 2. 监控 "ForwardMessageToSelectConversation] start" 字符串页
# 3. 等待转发，立即捕获
#
# 结果应能告诉我们：
#   - 函数在 0x9BF35A0 时的 args（CGI object 等）
#   - ForwardMessage 函数的入口地址（从 MemoryAccessMonitor）

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

WX_BASE = 0x2D0000
FN_PROLOGUE = 0x9BF35A0   # abs, function containing "before compress"

# "ForwardMessageToSelectConversation] start" @ RVA 0x0b02f529
FWD_MSG_STR_ABS = WX_BASE + 0x0b02f529  # = 0x0B2FF529

JS = r"""
'use strict';
var WX_BASE = 0x2D0000;
var FN_PROLOGUE = ptr(""" + hex(FN_PROLOGUE) + r""");
var FWD_STR_PAGE = ptr(""" + hex(FWD_MSG_STR_ABS & ~0xFFF) + r""");

var fn_captures = [];
var fwd_accesses = [];
var MAX = 50;
var monitoring = false;

function toHex(p, n) {
    try {
        var b = p.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return ''; }
}

// ── 1. Hook fn prologue at FN_PROLOGUE ─────────────────────────────────────
try {
    Interceptor.attach(FN_PROLOGUE, {
        onEnter: function(args) {
            if (fn_captures.length >= MAX) return;
            var ctx = this.context;
            var rec = {
                ts: Date.now(),
                regs: {
                    eax: ctx.eax.toString(), ecx: ctx.ecx.toString(),
                    edx: ctx.edx.toString(), ebx: ctx.ebx.toString(),
                    esp: ctx.esp.toString(), ebp: ctx.ebp.toString(),
                    esi: ctx.esi.toString(), edi: ctx.edi.toString()
                },
                args: []
            };
            for (var j=0; j<8; j++) {
                try {
                    var av = args[j].toInt32();
                    var s = '';
                    if (av > 0x100000 && av < 0x7fffffff) {
                        try { s = ptr(av).readCString(128) || ''; } catch(e) {}
                    }
                    rec.args.push({v: av.toString(16), s: s.substr(0,80)});
                } catch(e) { rec.args.push({v:'?'}); }
            }
            // 读 [ebp+8] 的 512 字节
            try {
                var ebp8 = ctx.ebp.readPointer().readPointer(); // [EBP+8]? no...
                // 实际：读 args[0..3] 所指向的内容
            } catch(e) {}
            fn_captures.push(rec);
            send({t:'fn_hit', n: fn_captures.length,
                  ecx: ctx.ecx.toString(), esi: ctx.esi.toString()});
        }
    });
    send({t:'fn_attached', addr: FN_PROLOGUE.toString()});
} catch(e) {
    send({t:'fn_err', msg: e.message});
}

// ── 2. MemoryAccessMonitor on ForwardMessage string page ───────────────────
try {
    MemoryAccessMonitor.enable([{base: FWD_STR_PAGE, size: 0x1000}], {
        onAccess: function(details) {
            if (!monitoring) return;
            fwd_accesses.push({
                from: details.from.toString(),
                op: details.operation,
                addr: details.address.toString()
            });
            if (fwd_accesses.length === 1) {
                send({t:'fwd_access', from: details.from.toString(),
                      rva: '0x' + (parseInt(details.from.toString())-WX_BASE).toString(16)});
            }
        }
    });
    send({t:'monitor_ready', page: FWD_STR_PAGE.toString()});
} catch(e) {
    send({t:'monitor_err', msg: e.message});
}

recv('start', function(_) { monitoring = true; send({t:'ack'}); });
recv('dump', function(_) {
    monitoring = false;
    // 读所有 fn_captures 中 args 指向的完整数据
    var enriched = fn_captures.slice(0, 10).map(function(r) {
        r.arg_data = [];
        r.args.forEach(function(a) {
            var v = parseInt(a.v, 16);
            var d = '';
            if (v > 0x100000 && v < 0x7fffffff) {
                d = toHex(ptr(v), 512);
            }
            r.arg_data.push({v: a.v, hex: d, str: a.s});
        });
        return r;
    });
    send({t:'dump_result', fn_captures: enriched, fwd_accesses: fwd_accesses});
});

send({t:'ready'});
"""

fn_captures = []
fwd_accesses = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description','')[:300], flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t in ('fn_attached','fn_err','monitor_ready','monitor_err','ack','ready'):
        print('[%s] %s' % (t, str(p)[:150]), flush=True)
    elif t == 'fn_hit':
        print('  [FN HIT #%d] ECX=%s ESI=%s' % (p.get('n'), p.get('ecx'), p.get('esi')), flush=True)
    elif t == 'fwd_access':
        print('  [FWD MONITOR HIT] from=%s  RVA=%s' % (p.get('from'), p.get('rva')), flush=True)
    elif t == 'dump_result':
        fn_captures.extend(p.get('fn_captures', []))
        fwd_accesses.extend(p.get('fwd_accesses', []))
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print('\n=== 请在 60 秒内转发消息 ===', flush=True)
sc.post({'type': 'start'})
time.sleep(60)

sc.post({'type': 'dump'})
dump_event.wait(15)

print(f'\n[+] fn_hits={len(fn_captures)}  fwd_accesses={len(fwd_accesses)}', flush=True)

def find_strs(hexdata, min_len=5):
    if not hexdata: return []
    try:
        bs = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    results = []
    for enc, decoder in [('u8','utf-8'), ('u16','utf-16-le')]:
        s = bs.decode(decoder, errors='ignore')
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s):
            w = m.group().strip()
            if w: results.append((enc, w))
    return results[:8]

for i, cap in enumerate(fn_captures[:5]):
    print(f'\n=== FN HIT #{i+1} ===', flush=True)
    for j, ad in enumerate(cap.get('arg_data', [])):
        strs = find_strs(ad.get('hex',''))
        if strs or ad.get('str'):
            print('  arg[%d]=0x%s  str=%r' % (j, ad.get('v',''), (ad.get('str','')[:60])), flush=True)
            for enc, s in strs[:4]:
                if not re.search(r'\.xml|weclaw|bubble|RtlAlloc', s):
                    print('    [%s] %r' % (enc, s[:100]), flush=True)

for acc in fwd_accesses[:10]:
    rva = int(acc.get('from','0'), 16) - WX_BASE
    print('FWD ACCESS: from=%s  RVA=0x%x' % (acc.get('from'), rva), flush=True)

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / ('fn_prologue_%s.json' % ts)
out.write_text(json.dumps({
    'fn_captures': fn_captures, 'fwd_accesses': fwd_accesses
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] 保存: {out}', flush=True)

os._exit(0)
