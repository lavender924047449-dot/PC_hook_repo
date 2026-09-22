# cgi_wait_forward.py
# 等待模式：不设固定时间窗口，检测到第一个转发 HIT 后再开始 60s 深度采集
# 用户可以随时转发，脚本会自动开始计时
#
# 执行后等待提示，然后在企微转发：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/cgi_wait_forward.py

import frida, subprocess, time, json, sys, os, threading, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
COLLECT_SEC_AFTER_FIRST_HIT = 60  # 收到第一个 HIT 后再采集多久
MAX_CAP_PER = 100

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
    '01004179':true,'01006300':true,'01006c00':true,
    '01006d00':true,'01016135':true,'0161a92e':true,'01cbb414':true
};

var captures = {};
var totalHit = 0;
var fwdHit = 0;
var firstHitTs = 0;
var capturing = false;
var MAX_PER = 100;

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
    var bytes = hexStr.split(' ').map(function(h){ return parseInt(h,16)||0; });
    var results = {};
    for (var i=0; i+3<bytes.length; i+=4) {
        var val = bytes[i] | (bytes[i+1]<<8) | (bytes[i+2]<<16) | (bytes[i+3]<<24);
        if (val > 0x200000 && val < 0x7fffffff) {
            var key = (val>>>0).toString(16);
            if (!results[key]) {
                try {
                    var data = toHex(ptr(val>>>0), 256);
                    if (data !== 'ERR') results[key] = data;
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
        fwdHit++;

        if (!capturing) {
            capturing = true;
            firstHitTs = Date.now();
            send({t:'first_hit', compact: c, ts: firstHitTs});
        }

        if (!captures[c]) captures[c] = [];
        if (captures[c].length >= MAX_PER) return;

        var a1_512 = toHex(args[1], 512);
        var ptrs = followPtrs(a1_512);
        captures[c].push({ts: Date.now(), a1_512: a1_512, ptrs: ptrs});

        if (fwdHit % 5 === 0) {
            send({t:'progress', fwdHit: fwdHit, totalHit: totalHit});
        }
    }
});

recv('dump', function(_) {
    send({t:'dump_result', captures: captures, totalHit: totalHit, fwdHit: fwdHit});
});

send({t:'ready', addr: HOOK.toString(), base: wxBase.toString()});
"""

all_captures = {}
dump_event = threading.Event()
first_hit_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[Frida ERR] {msg.get("description","")[:200]}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print(f'[+] Hook READY @ {p.get("addr")}  base={p.get("base")}', flush=True)
    elif t == 'first_hit':
        print(f'\n🎯 [第一个转发 HIT！ compact={p.get("compact")}] 开始采集 {COLLECT_SEC_AFTER_FIRST_HIT}s...', flush=True)
        first_hit_event.set()
    elif t == 'progress':
        print(f'  ... fwdHit={p.get("fwdHit")} totalHit={p.get("totalHit")}', flush=True)
    elif t == 'dump_result':
        all_captures.update(p.get('captures', {}))
        print(f'[+] Dump: patterns={list(all_captures.keys())} fwdHit={p.get("fwdHit")} totalHit={p.get("totalHit")}', flush=True)
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print(f'\n{"="*60}', flush=True)
print(f'★★★ 请在企微执行消息转发！★★★', flush=True)
print(f'  右键消息 → 转发 → 选联系人 → 发送', flush=True)
print(f'  脚本会在收到第一个 HIT 后自动计时 {COLLECT_SEC_AFTER_FIRST_HIT}s', flush=True)
print(f'  可以随时操作，无时间压力', flush=True)
print(f'{"="*60}\n', flush=True)

# 等待第一个转发 HIT（无超时，无限等待）
print('[*] 等待转发操作...', flush=True)
first_hit_event.wait()
print(f'[*] 采集中... 请继续多次转发以收集更多数据', flush=True)
time.sleep(COLLECT_SEC_AFTER_FIRST_HIT)

print('[*] 正在 dump...', flush=True)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ──────────────────────────────────────────────────────────────────────
def find_strings(hexdata, min_len=4):
    try:
        bs = bytes.fromhex(hexdata.replace(' ', ''))
    except:
        return []
    results = []
    try:
        s = bs.decode('utf-8', errors='ignore')
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff\u3400-\u4dbf]{%d,}' % min_len, s):
            w = m.group().strip()
            if w: results.append(('utf8', w))
    except: pass
    try:
        s16 = bs.decode('utf-16-le', errors='ignore')
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff\u3400-\u4dbf]{%d,}' % min_len, s16):
            w = m.group().strip()
            if w: results.append(('utf16', w))
    except: pass
    # 过滤掉明显的代码片段
    def is_code(s):
        code_markers = ['D$', 'L$', 'T$', 'l$', 't$', ']_^', 'PUSH', 'MOV', 'f\x00']
        return any(m in s for m in code_markers)
    return [(e, s) for e, s in results if not is_code(s)][:12]

print(f'\n{"="*60}', flush=True)
print('[=== 可读字符串汇总（过滤代码片段后） ===]', flush=True)

for compact, recs in sorted(all_captures.items()):
    print(f'\n--- pattern={compact}  ({len(recs)} 条) ---', flush=True)
    r = recs[0]
    strs_a1 = find_strings(r['a1_512'])
    if strs_a1:
        print(f'  a1 strings:', flush=True)
        for enc, s in strs_a1:
            print(f'    [{enc}] {s[:100]!r}', flush=True)
    ptr_strs_all = []
    for ptr_addr, ptr_data in sorted(r.get('ptrs', {}).items()):
        strs = find_strings(ptr_data)
        for enc, s in strs:
            ptr_strs_all.append((ptr_addr, enc, s))
    if ptr_strs_all:
        print(f'  deref strings ({len(ptr_strs_all)}):', flush=True)
        for addr, enc, s in ptr_strs_all[:30]:
            print(f'    [{enc}] @0x{addr}: {s[:100]!r}', flush=True)

# 保存
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'cgi_wait_{ts_str}.json'
out_path.write_text(json.dumps(all_captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out_path}', flush=True)

os._exit(0)
