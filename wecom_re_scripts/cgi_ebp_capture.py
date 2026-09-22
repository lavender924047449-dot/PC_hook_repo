# cgi_ebp_capture.py
# 在 0x390B39 (test eax,eax 之后) 通过 this.context.ebp 读取本地参数缓冲区 [ebp-0x54]
# 该缓冲区由内层函数 0x660CE0 填充，含当前 CGI 参数的实际内容
# 同时读取 args[1] (= ebx = CGI 请求对象指针，用于区分请求类型)
#
# 执行：请在 90s 内多次转发消息
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/cgi_ebp_capture.py

import frida, subprocess, time, json, sys, os, threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CAPTURE_SEC = 90
MAX_CAPTURES = 500

# 上一步确认的 7 个转发专属 compact 模式
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
var MAX_CAP = 500;

function toHex(ptr, n) {
    try {
        var b = ptr.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return 'ERR:'+e.message; }
}

function compact4(ptr) {
    try {
        var b = ptr.readByteArray(4);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join('');
    } catch(e) { return ''; }
}

Interceptor.attach(HOOK, {
    onEnter: function(args) {
        totalHit++;
        if (captures.length >= MAX_CAP) return;

        // args[1] = ebx = CGI 请求对象指针 (用于分类)
        var c = compact4(args[1]);
        if (!FWD_SET[c]) return;

        // 读取 [ebp-0x54] = 内层函数填充的本地参数缓冲区
        var ebp = this.context.ebp;
        var localBuf = ebp.sub(0x54);

        // 同时读取 [ebp-0x20] 和 [ebp-0x18] (其他本地变量)
        var rec = {
            ts: Date.now(),
            compact: c,
            a1_32: toHex(args[1], 32),       // CGI 请求对象头
            ebp_54: toHex(localBuf, 64),       // [ebp-0x54]: 本地参数缓冲区
            ebp_20: toHex(ebp.sub(0x20), 32), // [ebp-0x20]: 可能含迭代状态
            ebp_18: toHex(ebp.sub(0x18), 8),  // [ebp-0x18]: 某个计数/指针
            eax: this.context.eax.toString(),  // 返回值（1=成功,0=结束）
        };
        captures.push(rec);
        send({t:'hit', idx: captures.length, compact: c});
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
        if p.get('idx', 0) % 10 == 1:
            print(f'  [HIT #{p.get("idx")}] {p.get("compact")}', flush=True)
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
print(f'★★★ 请在企微多次转发不同类型消息（文字/图片/文件） ★★★', flush=True)
print(f'  有 {CAPTURE_SEC}s 时间窗口', flush=True)
print(f'{"="*60}\n', flush=True)

time.sleep(CAPTURE_SEC)
print('[*] 正在 dump...', flush=True)
sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

# 分析：按 compact 分组，打印第一条的 ebp_54 内容
print(f'\n{"="*60}', flush=True)
print('[=== ebp-0x54 本地参数缓冲区分析 ===]', flush=True)
seen = {}
for r in all_captures:
    c = r['compact']
    if c not in seen:
        seen[c] = r

for c, r in sorted(seen.items()):
    ebp54_hex = r['ebp_54']
    bs = bytes.fromhex(ebp54_hex.replace(' ', ''))
    print(f'\n--- compact={c} ---', flush=True)
    print(f'  a1[0:16]: {r["a1_32"][:47]}', flush=True)
    print(f'  ebp-0x54 (64 bytes):', flush=True)
    for i in range(0, len(bs), 16):
        row = bs[i:i+16]
        hx = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        print(f'    {i:04x}: {hx:<47}  {asc}', flush=True)
    # 尝试 UTF-8 和 UTF-16LE 解码
    try:
        s8 = bs.decode('utf-8', errors='ignore')
        readable8 = ''.join(c for c in s8 if c.isprintable())
        if len(readable8) > 4:
            print(f'  UTF-8 readable: {readable8[:80]!r}', flush=True)
    except: pass
    try:
        s16 = bs.decode('utf-16-le', errors='ignore')
        readable16 = ''.join(c for c in s16 if c.isprintable())
        if len(readable16) > 4:
            print(f'  UTF-16LE readable: {readable16[:60]!r}', flush=True)
    except: pass

# 保存完整数据
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'cgi_ebp_{ts_str}.json'
out_path.write_text(json.dumps(all_captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out_path}', flush=True)

os._exit(0)
