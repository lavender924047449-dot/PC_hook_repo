# hook_plaintext.py
# 挂钩 f2_top (0x990e58a)，读 arg[2] 完整 512 字节 + 指针 deref
# 目标：找到消息明文（XML/Protobuf格式）

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
print(f'[+] PID = {pid}', flush=True)

JS = """
'use strict';
var HOOK_ADDR = 0x990e58a;
var captures = [];
var MAX = 60;

function toHex(p, n) {
    try {
        var b = p.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return ''; }
}

function followPtrs(hexData) {
    var bytes = hexData.split(' ').map(function(h){ return parseInt(h,16)||0; });
    var out = {};
    for (var i=0; i+3<bytes.length; i+=4) {
        var v = bytes[i]|(bytes[i+1]<<8)|(bytes[i+2]<<16)|(bytes[i+3]<<24);
        if (v > 0x200000 && v < 0x7fffffff) {
            var k = (v>>>0).toString(16);
            if (!out[k]) {
                var d = toHex(ptr(v>>>0), 256);
                if (d) out[k] = d;
            }
        }
    }
    return out;
}

Interceptor.attach(ptr(HOOK_ADDR), {
    onEnter: function(args) {
        if (captures.length >= MAX) return;
        var a2 = args[2];
        var a2i = a2.toInt32();
        if (a2i < 0x200000 || a2i > 0x7fffffff) return;

        var a2_hex = toHex(a2, 512);
        var ptrs = followPtrs(a2_hex);

        // 也读 arg[1] 和 arg[3]
        var a1_hex = toHex(args[1], 128);
        var a3_hex = toHex(args[3], 128);

        captures.push({
            ts: Date.now(),
            a1: a1_hex,
            a2_addr: a2.toString(),
            a2: a2_hex,
            a3: a3_hex,
            ptrs: ptrs
        });
        send({t:'hit', n: captures.length, a2addr: a2.toString()});
    }
});

recv('dump', function(_) {
    send({t:'dump_result', captures: captures});
});

send({t:'ready', addr: '0x' + HOOK_ADDR.toString(16)});
"""

all_caps = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}', flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print(f'[+] Hook READY @ {p.get("addr")}', flush=True)
    elif t == 'hit':
        print(f'  [HIT #{p.get("n")}] arg[2]={p.get("a2addr")}', flush=True)
    elif t == 'dump_result':
        all_caps.extend(p.get('captures', []))
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print('\n=== 请在 45 秒内转发消息（可多次）===', flush=True)
print('右键消息 → 转发 → 选联系人 → 发送', flush=True)
time.sleep(45)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────
def find_strs(hexdata, min_len=4):
    try:
        bs = bytes.fromhex(hexdata.replace(' ', ''))
    except:
        return []
    results = []
    # UTF-8
    s = bs.decode('utf-8', errors='ignore')
    for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff\u3400-\u4dbf]{%d,}' % min_len, s):
        w = m.group().strip()
        if w and not re.match(r'^[.\-_/\\*]+$', w):
            results.append(('u8', w))
    # UTF-16LE
    s16 = bs.decode('utf-16-le', errors='ignore')
    for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff\u3400-\u4dbf]{%d,}' % min_len, s16):
        w = m.group().strip()
        if w and not re.match(r'^[.\-_/\\*]+$', w):
            results.append(('u16', w))
    return results[:15]

print(f'\n[+] 共 {len(all_caps)} 条', flush=True)

for i, cap in enumerate(all_caps[:10]):
    print(f'\n=== capture #{i+1}  a2={cap["a2_addr"]} ===', flush=True)
    # a2 字符串
    strs = find_strs(cap['a2'])
    if strs:
        print('  a2 strings:', flush=True)
        for enc, s in strs:
            print(f'    [{enc}] {s[:120]!r}', flush=True)
    # deref 指针
    for addr, hexd in sorted(cap['ptrs'].items()):
        strs2 = find_strs(hexd)
        useful = [(e, s) for e, s in strs2
                  if not re.search(r'[D-Z]\$[0-9A-Za-z]|RtlAlloc', s)
                  and len(s) > 4]
        if useful:
            print(f'  deref @0x{addr}:', flush=True)
            for enc, s in useful[:8]:
                print(f'    [{enc}] {s[:120]!r}', flush=True)

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'plaintext_{ts}.json'
out.write_text(json.dumps(all_caps, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}', flush=True)

os._exit(0)
