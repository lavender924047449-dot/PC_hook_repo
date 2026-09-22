# cgi_deep_deref.py
# 在 0x390B39 hook 处读取 [ebp-0x54] 的前两个指针，再 deref 128 字节
# 这两个指针是"提取出的参数数据"的 begin/end 或 (data_ptr, meta_ptr)
# 同时从 a1 (CGI 请求对象) 偏移 0x10 处起读取更多字节以找可读字符串
#
# 执行：请在 60s 内多次转发消息
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/cgi_deep_deref.py

import frida, subprocess, time, json, sys, os, threading
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CAPTURE_SEC = 60
MAX_CAPTURES = 300

FWD_COMPACT = {
    '01004179', '01006300', '01006c00', '01006d00',
    '01016135', '0161a92e', '01cbb414'
}

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID = {pid}', flush=True)

JS = r"""
'use strict';
var wxBase = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
}).base;
var HOOK = wxBase.add(0x390B39);

var FWD_SET = {
    '01004179': true, '01006300': true, '01006c00': true,
    '01006d00': true, '01016135': true, '0161a92e': true,
    '01cbb414': true
};

var captures = [];
var totalHit = 0;
var MAX_CAP = 300;

function toHex(ptr, n) {
    try {
        var b = ptr.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return 'ERR'; }
}

function compact4(ptr) {
    try {
        var b = ptr.readByteArray(4);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join('');
    } catch(e) { return ''; }
}

function safeReadPtr(ptr, offset) {
    try { return ptr.add(offset).readPointer(); } catch(e) { return null; }
}

Interceptor.attach(HOOK, {
    onEnter: function(args) {
        totalHit++;
        if (captures.length >= MAX_CAP) return;

        var c = compact4(args[1]);
        if (!FWD_SET[c]) return;

        var ebp = this.context.ebp;
        var localBuf = ebp.sub(0x54);  // [ebp-0x54]

        // 读取本地缓冲区的前 2 个指针
        var ptr0 = safeReadPtr(localBuf, 0);  // begin ptr
        var ptr1 = safeReadPtr(localBuf, 4);  // end ptr (or meta ptr)

        var deref0 = 'NULL';
        var deref1 = 'NULL';
        var size01 = 0;

        if (ptr0 !== null) {
            var p0val = ptr0.toUInt32();
            if (p0val > 0x10000 && p0val < 0x80000000) {
                deref0 = toHex(ptr0, 128);
            } else {
                deref0 = 'INVALID:' + ptr0.toString();
            }
        }
        if (ptr1 !== null) {
            var p1val = ptr1.toUInt32();
            if (p1val > 0x10000 && p1val < 0x80000000) {
                deref1 = toHex(ptr1, 64);
                if (ptr0 !== null) {
                    // size = ptr1 - ptr0 (if end > begin)
                    var diff = ptr1.toUInt32() - ptr0.toUInt32();
                    size01 = (diff < 0x10000) ? diff : -1;
                }
            } else {
                deref1 = 'INVALID:' + ptr1.toString();
            }
        }

        // 读取 args[1] (CGI 请求对象) 更多字节 (64 bytes, 含 UTF-16 key)
        var a1_64 = toHex(args[1], 64);

        var rec = {
            ts: Date.now(),
            compact: c,
            a1_64: a1_64,
            ptr0: ptr0 ? ptr0.toString() : 'NULL',
            ptr1: ptr1 ? ptr1.toString() : 'NULL',
            size01: size01,
            deref0: deref0,    // 128 bytes at ptr0
            deref1: deref1,    // 64 bytes at ptr1
        };
        captures.push(rec);
        if (captures.length % 20 === 1) {
            send({t:'hit', idx: captures.length, compact: c,
                  ptr0: rec.ptr0, ptr1: rec.ptr1, size: size01});
        }
    }
});

recv('dump', function(_) {
    send({t:'dump_result', captures: captures, totalHit: totalHit});
});

send({t:'ready', addr: HOOK.toString(), base: wxBase.toString()});
"""

all_captures = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[Frida ERR] {msg.get("description","")}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print(f'[+] Hook READY @ {p.get("addr")}  base={p.get("base")}', flush=True)
    elif t == 'hit':
        print(f'  [HIT #{p.get("idx")}] {p.get("compact")}  ptr0={p.get("ptr0")}  size={p.get("size")}', flush=True)
    elif t == 'dump_result':
        all_captures.extend(p.get('captures', []))
        print(f'[+] Dump: {len(all_captures)} 条, totalHit={p.get("totalHit")}', flush=True)
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print(f'\n{"="*60}', flush=True)
print(f'★★★ 请在企微多次转发消息 ★★★  ({CAPTURE_SEC}s 窗口)', flush=True)
print(f'{"="*60}\n', flush=True)

time.sleep(CAPTURE_SEC)
print('[*] 正在 dump...', flush=True)
sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

# 分析
print(f'\n{"="*60}', flush=True)
print('[=== 深层指针 deref 分析 ===]', flush=True)

seen = {}
for r in all_captures:
    c = r['compact']
    if c not in seen:
        seen[c] = r

for c, r in sorted(seen.items()):
    print(f'\n--- compact={c}  size={r["size01"]} ---', flush=True)
    # a1_64 可读字符串
    try:
        a1bs = bytes.fromhex(r['a1_64'].replace(' ',''))
        s16 = a1bs.decode('utf-16-le', errors='ignore')
        printable = ''.join(ch for ch in s16 if ch.isprintable())
        if printable:
            print(f'  a1 UTF-16: {printable[:80]!r}', flush=True)
    except: pass

    # deref0 (128 bytes from ptr0)
    print(f'  ptr0={r["ptr0"]}:', flush=True)
    if r['deref0'] and not r['deref0'].startswith('ERR') and not r['deref0'].startswith('INVALID') and not r['deref0'].startswith('NULL'):
        try:
            bs = bytes.fromhex(r['deref0'].replace(' ',''))
            for i in range(0, min(len(bs), 64), 16):
                row = bs[i:i+16]
                hx = ' '.join(f'{b:02x}' for b in row)
                asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
                print(f'    {i:04x}: {hx:<47}  {asc}', flush=True)
            # 搜索可读字符串
            s8 = bs.decode('utf-8', errors='ignore')
            r8 = ''.join(ch for ch in s8 if ch.isprintable())
            if len(r8) > 4:
                print(f'  deref0 UTF-8: {r8[:80]!r}', flush=True)
            s16 = bs.decode('utf-16-le', errors='ignore')
            r16 = ''.join(ch for ch in s16 if ch.isprintable())
            if len(r16) > 4:
                print(f'  deref0 UTF-16: {r16[:60]!r}', flush=True)
        except: pass
    else:
        print(f'    {r["deref0"][:60]}', flush=True)

# 保存
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'cgi_deep_{ts_str}.json'
out_path.write_text(json.dumps(all_captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out_path}', flush=True)

os._exit(0)
