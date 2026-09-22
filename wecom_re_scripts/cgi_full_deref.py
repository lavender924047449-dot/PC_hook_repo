# cgi_full_deref.py
# 在 0x390B39 对转发专属 pattern 做"指针喷射"深层 deref：
#   1. 读 args[1] 512 字节（CGI 请求对象全量）
#   2. 扫描其中所有 4 字节堆指针（0x10000 ~ 0x7FFFFFFF）
#   3. 对每个指针 deref 256 字节
#   4. 全部搜索 UTF-8/UTF-16 可读字符串 → 找联系人名/消息文本
#
# 执行（用户请在 60s 内多次转发消息）：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/cgi_full_deref.py

import frida, subprocess, time, json, sys, os, threading
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CAPTURE_SEC = 60
MAX_CAP = 50   # 每种 pattern 最多留 50 条（避免数据爆炸）

FWD_SET_LIST = [
    '01004179', '01006300', '01006c00', '01006d00',
    '01016135', '0161a92e', '01cbb414'
]

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

var FWD_SET = {};
var FWD_LIST = ['01004179','01006300','01006c00','01006d00','01016135','0161a92e','01cbb414'];
for (var fi=0; fi<FWD_LIST.length; fi++) FWD_SET[FWD_LIST[fi]] = true;

var captures = {};   // compact -> [{...}]
var totalHit = 0;
var MAX_PER = 50;

function compact4(ptr) {
    try {
        var b = ptr.readByteArray(4);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join('');
    } catch(e) { return ''; }
}

function toHex(ptr, n) {
    try {
        var b = ptr.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return 'ERR'; }
}

function followPtrs(hexStr) {
    // 从 hex 字符串扫描所有像堆指针的 4 字节值，deref 256 字节
    var bytes = hexStr.split(' ').map(function(h){ return parseInt(h,16); });
    var results = {};
    for (var i=0; i+3<bytes.length; i+=4) {
        var val = bytes[i] | (bytes[i+1]<<8) | (bytes[i+2]<<16) | (bytes[i+3]<<24);
        if (val > 0x10000 && val < 0x7fffffff) {
            var key = '0x' + ('00000000' + (val>>>0).toString(16)).slice(-8);
            if (!results[key]) {
                try {
                    var p = ptr(val);
                    var sub = toHex(p, 256);
                    if (sub !== 'ERR') results[key] = sub;
                } catch(e) {}
            }
        }
    }
    return results;
}

Interceptor.attach(HOOK, {
    onEnter: function(args) {
        totalHit++;
        var c = compact4(args[1]);
        if (!FWD_SET[c]) return;
        if (!captures[c]) captures[c] = [];
        if (captures[c].length >= MAX_PER) return;

        var a1_512 = toHex(args[1], 512);
        var ptrs = followPtrs(a1_512);
        captures[c].push({
            ts: Date.now(),
            a1_512: a1_512,
            ptrs: ptrs
        });
        send({t:'hit', compact: c, idx: captures[c].length});
    }
});

recv('dump', function(_) {
    send({t:'dump_result', captures: captures, totalHit: totalHit});
});

send({t:'ready', addr: HOOK.toString(), base: wxBase.toString()});
"""

all_captures = {}
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[Frida ERR] {msg.get("description","")[:200]}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print(f'[+] Hook READY @ {p.get("addr")}  base={p.get("base")}', flush=True)
    elif t == 'hit':
        print(f'  [HIT] {p.get("compact")} #{p.get("idx")}', flush=True)
    elif t == 'dump_result':
        all_captures.update(p.get('captures', {}))
        print(f'[+] Dump: patterns={list(all_captures.keys())} totalHit={p.get("totalHit")}', flush=True)
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print(f'\n{"="*60}', flush=True)
print(f'★★★ 请在企微多次转发消息！★★★  ({CAPTURE_SEC}s 窗口)', flush=True)
print(f'  右键消息 → 转发 → 选联系人 → 发送（可重复多次）', flush=True)
print(f'{"="*60}\n', flush=True)

time.sleep(CAPTURE_SEC)
print('[*] 正在 dump...', flush=True)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ──────────────────────────────────────────────────────────────────────
def find_strings(hexdata, min_len=4):
    """在 hex 数据中搜索 UTF-8 和 UTF-16LE 可读字符串"""
    try:
        bs = bytes.fromhex(hexdata.replace(' ', ''))
    except:
        return []
    results = []
    # UTF-8
    try:
        s = bs.decode('utf-8', errors='ignore')
        import re
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff\u3400-\u4dbf]{%d,}' % min_len, s):
            w = m.group().strip()
            if w and len(w) >= min_len:
                results.append(('utf8', w))
    except: pass
    # UTF-16LE
    try:
        s16 = bs.decode('utf-16-le', errors='ignore')
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff\u3400-\u4dbf]{%d,}' % min_len, s16):
            w = m.group().strip()
            if w and len(w) >= min_len:
                results.append(('utf16', w))
    except: pass
    return results[:10]

import re
print(f'\n{"="*60}', flush=True)
print('[=== 可读字符串汇总 ===]', flush=True)

for compact, recs in sorted(all_captures.items()):
    print(f'\n--- pattern={compact}  ({len(recs)} 条) ---', flush=True)
    # 取第一条做分析
    r = recs[0]
    # 分析 a1 本身
    strs_a1 = find_strings(r['a1_512'])
    if strs_a1:
        print(f'  a1 strings: {strs_a1[:5]}', flush=True)
    # 分析所有 deref 指针
    ptr_strs_all = []
    for ptr_addr, ptr_data in sorted(r.get('ptrs', {}).items()):
        strs = find_strings(ptr_data)
        for enc, s in strs:
            ptr_strs_all.append((ptr_addr, enc, s))
    if ptr_strs_all:
        print(f'  deref strings ({len(ptr_strs_all)} total):', flush=True)
        for addr, enc, s in ptr_strs_all[:20]:
            print(f'    [{enc}] @{addr}: {s[:80]!r}', flush=True)

# 保存
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'cgi_full_{ts_str}.json'
out_path.write_text(json.dumps(all_captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out_path}', flush=True)

os._exit(0)
