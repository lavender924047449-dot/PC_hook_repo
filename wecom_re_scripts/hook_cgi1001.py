# hook_cgi1001.py
# 搜索 "cgi request:" 日志字符串 → 找到对应的 log 函数
# 在 log 调用前挂钩，捕获 CGI#1001 的 561 字节明文 Protobuf payload
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/hook_cgi1001.py

import frida, subprocess, sys, os, time, threading, json, re, struct
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

JS = r"""
'use strict';
var wxBase = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
}).base;

// 在内存中搜索 "cgi request:" 字符串
var CGI_LOG_STR = 'cgi request:';
var captures = [];
var MAX = 80;

function toHex(p, n) {
    try {
        var b = p.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return ''; }
}

// 扫描 WXWork.exe 全部内存范围查找 "cgi request:" 字符串
var wxMod = Process.getModuleByName('WXWork.exe');
var wxStart = wxMod.base;
var wxEnd = wxMod.base.add(wxMod.size);

var CGI_LOG_BYTES = [99,103,105,32,114,101,113,117,101,115,116,58]; // "cgi request:"
var CGI_LOG_N = CGI_LOG_BYTES.length;
var found_str_addrs = [];

// 分段扫描（避免一次读取整个巨大模块）
var CHUNK = 0x100000; // 1MB per chunk
var cur = wxStart;
while (cur.compare(wxEnd) < 0) {
    var end = cur.add(CHUNK);
    if (end.compare(wxEnd) > 0) end = wxEnd;
    try {
        var results = Memory.scanSync(cur, end.sub(cur).toInt32(),
            CGI_LOG_BYTES.map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' '));
        results.forEach(function(r) { found_str_addrs.push(r.address.toString()); });
    } catch(e) {}
    cur = end;
}

send({t:'scan_done', count: found_str_addrs.length, addrs: found_str_addrs.slice(0,5)});

// ─── 现在我们知道了 "cgi request:" 的地址，找 xref（哪里 push 这个地址）
// 由于 VMP，直接扫 PUSH/MOV 找 xref 可能失败，但还是试试
// 另一个方法：挂钩 f2_top，检测 CGI#1001（通过读 a2 的特定偏移）

// 从 hook_frames 和 plaintext 分析中我们知道：
// a2[0x7?:0x90] 包含 "cgi request:1001 before compress length XXX"
// 以及 a2[0x68:0x90] 包含 URL "https://i.work.weixin.qq.com/cgi-bin/key"

// 策略：挂 f2_top，检测 a2 中是否含 CGI#1001 日志字符串
// 如果是，则读 a2 附近的所有可能的 payload 指针

var F2_ADDR = 0x990e58a;

Interceptor.attach(ptr(F2_ADDR), {
    onEnter: function(args) {
        if (captures.length >= MAX) return;
        var a2 = args[2];
        var a2i = a2.toInt32();
        if (a2i < 0x200000 || a2i > 0x7fffffff) return;

        // 读 512 字节
        var a2_bytes = a2.readByteArray(512);
        if (!a2_bytes) return;
        var a2_arr = Array.from(new Uint8Array(a2_bytes));
        var a2_str = '';
        for (var k=0; k<a2_arr.length; k++) {
            var c = a2_arr[k];
            a2_str += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }

        // 检查是否含 CGI#1001
        var has1001 = a2_str.indexOf('cgi request:1001') >= 0;
        var hasURL = a2_str.indexOf('i.work.weixin') >= 0;
        var hasUUID = false;
        // 检查前 37 字节是否是 UUID 格式
        if (a2_arr[8] === 45 && a2_arr[13] === 45 && a2_arr[18] === 45 && a2_arr[23] === 45) {
            hasUUID = true;
        }

        if (!has1001 && !hasURL) return; // 不感兴趣

        // 读 1024 字节并搜索所有指针
        var a2_1024_hex = toHex(a2, 1024);
        var ptrs = {};
        var a2b = a2_arr;
        for (var i = 0; i+3 < 512; i += 4) {
            var v = a2b[i] | (a2b[i+1]<<8) | (a2b[i+2]<<16) | (a2b[i+3]<<24);
            if (v > 0x200000 && v < 0x7fffffff) {
                var k2 = (v>>>0).toString(16);
                if (!ptrs[k2]) {
                    var d = toHex(ptr(v>>>0), 512);
                    if (d) ptrs[k2] = d;
                }
            }
        }

        captures.push({
            ts: Date.now(),
            a2addr: a2.toString(),
            a2: a2_1024_hex,
            has1001: has1001,
            hasURL: hasURL,
            hasUUID: hasUUID,
            ptrs: ptrs
        });
        send({t:'hit', n: captures.length, has1001: has1001, hasURL: hasURL, addr: a2.toString()});
    }
});

recv('dump', function(_) {
    send({t:'dump_result', captures: captures, found_str_addrs: found_str_addrs});
});

send({t:'ready'});
"""

all_caps = []
found_addrs = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:300]}', flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print(f'[+] Script READY', flush=True)
    elif t == 'scan_done':
        found_addrs.extend(p.get('addrs', []))
        print(f'[+] 扫描完成: "cgi request:" 找到 {p.get("count")} 处', flush=True)
        print(f'  首5个地址: {p.get("addrs")}', flush=True)
    elif t == 'hit':
        flag = ''
        if p.get('has1001'): flag += ' [CGI#1001]'
        if p.get('hasURL'): flag += ' [URL]'
        print(f'  [HIT #{p.get("n")}] addr={p.get("addr")}{flag}', flush=True)
    elif t == 'dump_result':
        all_caps.extend(p.get('captures', []))
        found_addrs.extend(p.get('found_str_addrs', []))
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()

print('[*] 等待扫描完成...', flush=True)
time.sleep(5)  # wait for scan

print(f'\n=== 请在 60 秒内转发消息（可多次）===', flush=True)
print('右键消息 → 转发 → 选联系人 → 发送', flush=True)
time.sleep(60)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────

def decode_pb(data_bytes):
    """尝试简单 Protobuf 解码"""
    results = []
    i = 0
    while i < len(data_bytes):
        try:
            b = data_bytes[i]
            if b == 0: break
            field = b >> 3
            wire = b & 7
            i += 1
            if wire == 0:  # varint
                val = 0
                shift = 0
                while True:
                    vb = data_bytes[i]; i += 1
                    val |= (vb & 0x7f) << shift
                    shift += 7
                    if not (vb & 0x80): break
                results.append(('varint', field, val))
            elif wire == 2:  # length-delimited
                length = 0; shift = 0
                while True:
                    vb = data_bytes[i]; i += 1
                    length |= (vb & 0x7f) << shift
                    shift += 7
                    if not (vb & 0x80): break
                if length > 10000 or i + length > len(data_bytes): break
                payload = data_bytes[i:i+length]
                i += length
                try:
                    s = payload.decode('utf-8', errors='strict')
                    results.append(('string', field, s))
                except:
                    results.append(('bytes', field, payload.hex()))
            else:
                break
        except:
            break
    return results

print(f'\n[+] 总命中: {len(all_caps)}', flush=True)
print(f'[+] "cgi request:" 字符串地址: {found_addrs[:5]}', flush=True)

for i, cap in enumerate(all_caps[:10]):
    print(f'\n=== CGI#1001 capture #{i+1}  a2={cap["a2_addr"]} ===', flush=True)
    a2b = bytes.fromhex(cap['a2'].replace(' ',''))
    # 打印 a2 前 128 字节
    for off in range(0, min(128, len(a2b)), 16):
        row = a2b[off:off+16]
        hx = ' '.join('%02x' % b for b in row)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in row)
        print('  %04x: %-47s  %s' % (off, hx, asc), flush=True)
    # 在 a2 里找 "compress length" 附近数字
    s = a2b.decode('utf-8', errors='ignore')
    m = re.search(r'length (\d+)', s)
    if m:
        print(f'  payload length: {m.group(1)}', flush=True)
    # 在 deref 的指针里找可读内容和 Protobuf
    for addr, hexd in sorted(cap.get('ptrs', {}).items()):
        bs2 = bytes.fromhex(hexd.replace(' ',''))
        utf8 = ''.join(c for c in bs2.decode('utf-8', errors='ignore') if c.isprintable())
        if len(utf8) > 10 and not re.search(r'\.xml|bubble|ChatBubble|weclaw|Rtl', utf8):
            print(f'  deref @0x{addr}: {utf8[:120]!r}', flush=True)
        # 尝试 Protobuf 解码
        pb = decode_pb(bs2)
        if len(pb) > 2:
            print(f'  deref @0x{addr} Protobuf:', flush=True)
            for item in pb[:5]:
                print(f'    {item}', flush=True)

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'cgi1001_{ts}.json'
out.write_text(json.dumps(all_caps, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}', flush=True)

os._exit(0)
