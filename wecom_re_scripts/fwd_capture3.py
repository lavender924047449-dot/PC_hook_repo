# fwd_capture3.py -- 对转发专属 pattern 做深度抓包
# ===========================================================
# 上一步 cgi_diff2.py 发现了 7 个转发专属 a1[0:4] pattern，
# 本脚本针对这 7 个 pattern 做深度捕获:
#   a0: 32 bytes
#   a1: 32 bytes（完整看 pattern 结构）
#   a2_ptr: 读取 args[2] 值本身（是指针还是整数？）
#   a2_deref: 如果 args[2] 是有效指针，解引用 256 bytes
# 运行时间：90 秒，期间请多次转发消息（不同类型）
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/fwd_capture3.py

import frida, subprocess, time, json, sys, os, threading
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
RVA_CGI = 0x390B39

# 上一步捕获的 7 个转发专属 pattern（a1 前 4 字节）
FWD_PATTERNS = {
    "01 00 41 79",
    "01 00 63 00",
    "01 00 6c 00",
    "01 00 6d 00",
    "01 01 61 35",
    "01 61 a9 2e",
    "01 cb b4 14",
}

CAPTURE_SEC = 90
MAX_CAPTURES = 200  # 安全上限

def get_pid():
    o = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f"[+] PID = {pid}", flush=True)

JS = r"""
'use strict';
var wxBase = null;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxBase = mods[i].base; break;
    }
}
var HOOK = wxBase.add(0x390B39);

var FWD_PATS = {
    '010041 79': 1, '01006300': 1, '01006c00': 1, '01006d00': 1,
    '0101 6135': 1, '0161a92e': 1, '01cbb414': 1
};

// 转发专属 pattern set（hex string 紧凑格式）
var FWD_SET = {
    '01004179': true,
    '01006300': true,
    '01006c00': true,
    '01006d00': true,
    '010161 35': true,
    '0161a92e': true,
    '01cbb414': true,
};

var captures = [];
var hitAll = 0;
var MAX_CAP = 200;

function toHexN(ptr, n) {
    try {
        var b = ptr.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return 'ERR'; }
}

function toHex4compact(ptr) {
    try {
        var b = ptr.readByteArray(4);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join('');
    } catch(e) { return ''; }
}

Interceptor.attach(HOOK, {
    onEnter: function(args) {
        hitAll++;
        if (captures.length >= MAX_CAP) return;

        var compact = toHex4compact(args[1]);
        if (!FWD_SET[compact]) return;

        var a0 = toHexN(args[0], 32);
        var a1 = toHexN(args[1], 32);

        // args[2]: 先读原始指针值
        var a2_raw = 'ERR';
        var a2_deref = 'SKIP';
        try {
            a2_raw = args[2].toString();
            // 判断是否像有效指针（0x10000 ~ 0x7fffffff）
            var addr2 = args[2].toUInt32();
            if (addr2 > 0x10000 && addr2 < 0x80000000) {
                a2_deref = toHexN(args[2], 256);
            } else {
                a2_deref = 'NOT_PTR:' + a2_raw;
            }
        } catch(e) { a2_raw = 'EXC:' + e.message; }

        var rec = {
            ts: Date.now(),
            idx: captures.length,
            hitAll: hitAll,
            compact: compact,
            a0: a0,
            a1: a1,
            a2_raw: a2_raw,
            a2_deref: a2_deref,
        };
        captures.push(rec);
        send({t:'hit', idx: captures.length, compact: compact, a2_raw: a2_raw});
    }
});

recv('dump', function(_) {
    send({t:'dump_result', captures: captures, totalHit: hitAll});
});

send({t:'ready', base: wxBase.toString(), addr: HOOK.toString()});
"""

all_captures = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get("type") == "error":
        print(f"[Frida ERR] {msg.get('description','')}", flush=True)
        return
    if msg.get("type") != "send": return
    p = msg["payload"]
    t = p.get("t", "")
    if t == "ready":
        print(f"[+] Hook READY @ {p.get('addr')}  base={p.get('base')}", flush=True)
    elif t == "hit":
        print(f"  [HIT #{p.get('idx')}] compact={p.get('compact')}  a2_raw={p.get('a2_raw')}", flush=True)
    elif t == "dump_result":
        all_captures.extend(p.get("captures", []))
        print(f"[+] Dump 完成: {len(all_captures)} 条记录, totalHit={p.get('totalHit')}", flush=True)
        dump_event.set()

print("[*] Attaching...", flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_message)
sc.load()
time.sleep(1)

print(f"\n{'='*60}", flush=True)
print(f"★★★ 请在企微多次转发不同类型消息（文字/图片/文件）★★★", flush=True)
print(f"  有 {CAPTURE_SEC}s 时间窗口", flush=True)
print(f"{'='*60}\n", flush=True)

time.sleep(CAPTURE_SEC)

print("[*] 正在 dump 数据...", flush=True)
sc.post({"type": "dump"})
dump_event.wait(timeout=10)

# 保存
ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
out_path = OUT_DIR / f"fwd_capture3_{ts_str}.json"
out_path.write_text(json.dumps(all_captures, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[+] 结果保存: {out_path}  共 {len(all_captures)} 条", flush=True)

# 汇总每种 compact 的样本数
from collections import Counter
c = Counter(r["compact"] for r in all_captures)
print("\n[汇总] 各 pattern 捕获次数：", flush=True)
for k, v in c.most_common():
    print(f"  {k}: {v} 次", flush=True)

os._exit(0)
