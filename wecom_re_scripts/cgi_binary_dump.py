# cgi_binary_dump.py — P0: dump CGI#1001 before-compress plaintext proto (no ASCII filter)
#
# 策略（按 §45.10）：
#  1. hook wxBase + 0x963E58A (f2_top)
#  2. 过滤：arg2 同时含 "cgi request:1001" AND "before compress"
#  3. 解析 N（本轮预期 666，但可能变）
#  4. 候选源（无 ASCII 过滤，纯二进制 dump）：
#     a. args[3] / args[4] 直接 dump N 字节
#     b. args[0] 作为 "this" —— 扫 MSVC std::string{ptr@0, size@16==N}
#     c. 扫 arg2 前 2KB，找 dword==N → 取前 16 字节处的 ptr → dump N 字节
#     d. 追 arg2 前 512B 中所有有效指针，对每个被指对象再做 (c)
#  5. 每个候选写 .bin 文件 + 尝试 protobuf 解码
#
# 禁止：M3 / mitmproxy / 系统代理 / 0x99235A0 builder / SSL_write 主线
#
# 运行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' cgi_binary_dump.py
#   然后在企微窗口发一条文字、再发一个文件（或转发）

import frida, subprocess, sys, os, time, json, re, struct, base64
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
F2_TOP_RVA   = 0x963E58A
CAPTURE_SEC  = 90      # 给用户时间操作
MAX_CAP      = 15      # 最多抓 15 次有效命中（1001+before compress）

# ──────────────────────────────────────────────────────────────────────────────
# Frida JS（32 位 ia32 进程）
# ──────────────────────────────────────────────────────────────────────────────
JS = r"""
'use strict';

var wxBase  = Process.getModuleByName('WXWork.exe').base;
var hookPtr = wxBase.add(0x963E58A);
var n = 0;
var MAX = 15;

// ── 工具 ──────────────────────────────────────────────────────────────────────

function u32(arr, off) {
    return ((arr[off] | (arr[off+1]<<8) | (arr[off+2]<<16) | (arr[off+3]<<24)) >>> 0);
}

function safeBytes(addr, sz) {
    try {
        var p = ptr(addr);
        if (p.toUInt32() < 0x10000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}

function toB64(ab) {
    if (!ab) return null;
    // Frida 提供 base64 encode
    return Memory.alloc(1).readByteArray; // placeholder — 用 hex 代替
}

function toHex(ab) {
    if (!ab) return null;
    var a = new Uint8Array(ab);
    var s = '';
    for (var i = 0; i < a.length; i++) s += ('0' + a[i].toString(16)).slice(-2);
    return s;
}

function asciiIn(ab, minLen) {
    var a = new Uint8Array(ab);
    var out = [], run = '', start = 0;
    for (var i = 0; i < a.length; i++) {
        if (a[i] >= 32 && a[i] < 127) {
            if (!run.length) start = i;
            run += String.fromCharCode(a[i]);
        } else {
            if (run.length >= minLen) out.push({o: start, s: run});
            run = '';
        }
    }
    if (run.length >= minLen) out.push({o: start, s: run});
    return out;
}

// 在字节数组中找 dword==N (LE)，返回 [{off, ptrCandidate}]
// MSVC std::string 32bit heap：[ptr(4B) | pad(12B) | size(4B) | cap(4B)]
//   → size 在 ptr 之后偏移 16 处
// 也检查 off-4 处是否是有效指针（相邻 ptr+size 布局）
function findSizeN(ab, N) {
    var a = new Uint8Array(ab);
    var NL = N & 0xFF, N1 = (N>>8)&0xFF, N2 = (N>>16)&0xFF, N3 = (N>>24)&0xFF;
    var found = [];
    for (var i = 0; i + 3 < a.length; i += 4) {
        if (a[i]===NL && a[i+1]===N1 && a[i+2]===N2 && a[i+3]===N3) {
            // std::string layout: size @ off+16 → ptr @ off+0
            if (i >= 16) {
                var pv = u32(a, i - 16);
                if (pv > 0x10000 && pv < 0xFFFF0000)
                    found.push({off: i, src: 'str+16', p: pv});
            }
            // adjacent: dword at i-4 as ptr, dword at i as size
            if (i >= 4) {
                var pv2 = u32(a, i - 4);
                if (pv2 > 0x10000 && pv2 < 0xFFFF0000)
                    found.push({off: i, src: 'adj', p: pv2});
            }
            // also check i+4 as cap → ptr at i-16 already handled
            // dword at i as ptr (i.e. the size field IS at i and ptr IS right before at i-16)
        }
    }
    return found;
}

// 从对象内存中收集所有可能 heap 指针（4 字节对齐）
function heapPtrsIn(ab, limit) {
    var a = new Uint8Array(ab);
    var seen = {}, out = [];
    for (var i = 0; i + 3 < a.length && out.length < (limit||64); i += 4) {
        var pv = u32(a, i);
        if (pv > 0x10000 && pv < 0xFFFF0000) {
            var k = pv.toString(16);
            if (!seen[k]) { seen[k]=1; out.push(pv); }
        }
    }
    return out;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (n >= MAX) return;

        // 读 arg2（log 上下文）
        var a2v = args[2].toUInt32();
        var a2raw = safeBytes(a2v, 2048);
        if (!a2raw) return;

        var a2strs = asciiIn(a2raw, 6).map(function(x){ return x.s; }).join('|');
        var has1001   = a2strs.indexOf('cgi request:1001') >= 0;
        var hasBefore = a2strs.indexOf('before compress')  >= 0;
        if (!has1001 || !hasBefore) return;

        // 解析 N
        var mN = a2strs.match(/before compress length (\d+)/);
        if (!mN) return;
        var N = parseInt(mN[1]);
        n++;

        // ── 收集候选 ──────────────────────────────────────────────────────────
        var candidates = [];
        var seen = {};

        function tryAddr(addr, label) {
            if (!addr || addr < 0x10000 || addr > 0xFFFF0000) return;
            var k = addr.toString(16);
            if (seen[k]) return; seen[k] = 1;
            var raw = safeBytes(addr, N + 256);   // 多读 256B 以防对齐偏移
            if (!raw) return;
            candidates.push({
                src: label,
                addr: '0x' + addr.toString(16),
                hex: toHex(raw).slice(0, (N+256)*2),
                dump_n: N
            });
        }

        // 策略 a: args[3] / args[4] 直接 dump
        for (var ai = 3; ai <= 4; ai++) {
            var av = args[ai].toUInt32();
            tryAddr(av, 'args[' + ai + ']@0x' + av.toString(16));
        }

        // 策略 b: args[0] 作为 this—— 扫 MSVC string{size==N}
        var a0v = args[0].toUInt32();
        var a0raw = safeBytes(a0v, 512);
        if (a0raw) {
            var hits0 = findSizeN(a0raw, N);
            for (var hi = 0; hi < hits0.length && hi < 4; hi++) {
                tryAddr(hits0[hi].p, 'args[0]_str_' + hits0[hi].src + '_off' + hits0[hi].off);
            }
        }

        // 策略 c: 直接扫 arg2 前 2KB
        var hints2 = findSizeN(a2raw, N);
        for (var hi2 = 0; hi2 < hints2.length && hi2 < 6; hi2++) {
            tryAddr(hints2[hi2].p, 'a2scan_' + hints2[hi2].src + '_off' + hints2[hi2].off);
        }

        // 策略 d: 追 arg2 指针，对每个被指对象再扫
        var a2ptrs = heapPtrsIn(a2raw, 48);
        for (var pi = 0; pi < a2ptrs.length; pi++) {
            var prv = a2ptrs[pi];
            var praw = safeBytes(prv, 1024);
            if (!praw) continue;
            var hitsP = findSizeN(praw, N);
            for (var hj = 0; hj < hitsP.length && hj < 3; hj++) {
                tryAddr(hitsP[hj].p,
                    'a2ptr0x' + prv.toString(16) + '_' + hitsP[hj].src + '_off' + hitsP[hj].off);
            }
        }

        // 也直接把 arg2 的指针本身 dump N 字节（有时 arg2 的某个字段就是 payload ptr）
        for (var pi2 = 0; pi2 < a2ptrs.length && pi2 < 16; pi2++) {
            tryAddr(a2ptrs[pi2], 'a2ptr_direct_0x' + a2ptrs[pi2].toString(16));
        }

        // ── 发送 ──────────────────────────────────────────────────────────────
        send({
            t: 'hit',
            n: n,
            N: N,
            args: [
                '0x' + args[0].toUInt32().toString(16),
                '0x' + args[1].toUInt32().toString(16),
                '0x' + args[2].toUInt32().toString(16),
                '0x' + args[3].toUInt32().toString(16),
                '0x' + args[4].toUInt32().toString(16)
            ],
            a2_excerpt: a2strs.slice(0, 300),
            candidates: candidates
        });
    }
});

send({t: 'ready', hook: hookPtr.toString(), base: wxBase.toString()});
"""

# ──────────────────────────────────────────────────────────────────────────────
# Protobuf 解码（纯 Python，无需 protoc）
# ──────────────────────────────────────────────────────────────────────────────

def pb_decode(data: bytes, depth=0, max_fields=200) -> list:
    """轻量 protobuf wire-format 解码，返回 field 列表。"""
    fields = []
    i = 0
    while i < len(data) and len(fields) < max_fields:
        if data[i] == 0:
            break
        # 读 tag (varint)
        try:
            tag = 0; sh = 0
            while i < len(data):
                b = data[i]; i += 1
                tag |= (b & 0x7F) << sh; sh += 7
                if not (b & 0x80): break
                if sh > 35: raise ValueError('varint too long')
            wire = tag & 7
            fnum = tag >> 3
            if fnum == 0 or fnum > 100000:
                break
            if wire == 0:   # varint
                v = 0; sh2 = 0
                while i < len(data):
                    b = data[i]; i += 1
                    v |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                fields.append({'f': fnum, 'w': 'varint', 'v': v})
            elif wire == 1: # 64-bit
                if i + 8 > len(data): break
                v = int.from_bytes(data[i:i+8], 'little'); i += 8
                fields.append({'f': fnum, 'w': 'i64', 'v': hex(v)})
            elif wire == 2: # length-delimited
                ln = 0; sh2 = 0
                while i < len(data):
                    b = data[i]; i += 1
                    ln |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                if ln < 0 or ln > 200_000 or i + ln > len(data):
                    break
                payload = data[i:i+ln]; i += ln
                try:
                    s = payload.decode('utf-8')
                    fields.append({'f': fnum, 'w': 'str', 'v': s})
                except Exception:
                    sub = None
                    if depth < 3:
                        sub = pb_decode(payload, depth+1, 50)
                    fields.append({'f': fnum, 'w': 'bytes', 'len': ln,
                                   'hex': payload[:24].hex(), 'sub': sub})
            elif wire == 5: # 32-bit
                if i + 4 > len(data): break
                v = int.from_bytes(data[i:i+4], 'little'); i += 4
                fields.append({'f': fnum, 'w': 'i32', 'v': hex(v)})
            else:
                break
        except Exception:
            break
    return fields


def pb_score(fields: list) -> int:
    """给 proto 解码结果打分：字段多、有字符串、varint 合理 → 分高。"""
    score = 0
    for f in fields:
        score += 1
        if f['w'] == 'str':
            score += max(0, min(len(f['v']), 60)) // 5
        if f['w'] == 'varint' and 0 < f['v'] < 0xFFFFFFFF:
            score += 1
        if f.get('sub') and len(f['sub']) > 0:
            score += 2
    return score


def print_fields(fields, indent=0):
    pfx = '  ' * indent
    for f in fields[:30]:
        w = f['w']
        if w == 'str':
            print(f"{pfx}  f{f['f']}(str): {repr(f['v'][:120])}")
        elif w == 'varint':
            print(f"{pfx}  f{f['f']}(int): {f['v']}")
        elif w == 'bytes':
            sub_info = f'  sub[{len(f["sub"])}]' if f.get("sub") else ''
            print(f"{pfx}  f{f['f']}(bytes,{f['len']}): {f['hex']}{sub_info}")
            if f.get('sub'):
                print_fields(f['sub'], indent+1)
        elif w in ('i32','i64'):
            print(f"{pfx}  f{f['f']}({w}): {f['v']}")


# ──────────────────────────────────────────────────────────────────────────────
# 主程序
# ──────────────────────────────────────────────────────────────────────────────

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            pid = int(line.strip().split()[-1])
            print(f'  :9882 LISTENING → PID={pid}')
            return pid
    raise RuntimeError('未找到 :9882 LISTENING PID（企微是否在运行？）')


ts_str   = datetime.now().strftime('%Y%m%d_%H%M%S')
ndjson_p = OUT_DIR / f'cgi_binary_{ts_str}.ndjson'
hits_all = []

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:300]}', flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t', '')

    if t == 'ready':
        print(f'[+] HOOK @ {p.get("hook")}  wxBase={p.get("base")}', flush=True)
        return

    if t != 'hit':
        return

    cap = p
    hits_all.append(cap)

    N    = cap['N']
    cand = cap.get('candidates', [])

    print(f'\n{"="*70}', flush=True)
    print(f'★ HIT #{cap["n"]}  N={N}  args={cap["args"]}', flush=True)
    print(f'  a2: {cap.get("a2_excerpt","")[:200]}', flush=True)
    print(f'  候选数: {len(cand)}', flush=True)

    best_score = -1
    best_hex   = None
    best_src   = None

    for ci, c in enumerate(cand):
        raw_hex = c.get('hex', '')
        if not raw_hex:
            continue
        raw_bytes = bytes.fromhex(raw_hex[:N*2])   # 只取前 N 字节解码
        fields    = pb_decode(raw_bytes)
        score     = pb_score(fields)

        has_str = sum(1 for f in fields if f['w']=='str')
        print(f'\n  [{ci}] {c["src"]}  addr={c["addr"]}  score={score}  pb_fields={len(fields)}  strings={has_str}',
              flush=True)

        # 打印有意义的字段
        if fields and score >= 3:
            print_fields(fields[:15], indent=1)
        elif raw_bytes[:4] != b'\x00\x00\x00\x00':
            # 即使 proto decode 失败，也打印前 48 字节 hex
            print(f'    raw[0:48]={raw_bytes[:48].hex()}', flush=True)

        if score > best_score:
            best_score = score
            best_hex   = raw_hex[:N*2]
            best_src   = c['src']

        # 写候选 bin 文件
        bin_name = f'cgi_proto_{ts_str}_hit{cap["n"]}_c{ci}.bin'
        bin_path = OUT_DIR / bin_name
        bin_path.write_bytes(raw_bytes)
        print(f'    → 写入 {bin_name}', flush=True)

    # 最佳候选摘要
    if best_hex:
        print(f'\n  ✔ 最佳候选: [{best_src}]  score={best_score}', flush=True)

    # 写 ndjson
    with ndjson_p.open('a', encoding='utf-8') as f:
        f.write(json.dumps(cap, ensure_ascii=False) + '\n')


print('[*] 获取 PID...', flush=True)
pid = get_pid()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc   = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

print(f'\n{"="*70}', flush=True)
print(f'★★★ 请在 {CAPTURE_SEC}s 内：', flush=True)
print(f'    1. 在企微窗口发一条【文字消息】', flush=True)
print(f'    2. 再发一个【文件】（或转发）', flush=True)
print(f'    等待 HIT 出现…', flush=True)
print(f'{"="*70}', flush=True)

time.sleep(CAPTURE_SEC)

sc.unload()
sess.detach()

print(f'\n[+] 共捕获 {len(hits_all)} 次有效命中', flush=True)
print(f'[+] NDJSON → {ndjson_p}', flush=True)
print(f'[+] BIN 文件见 {OUT_DIR}', flush=True)

# 汇总最终最佳候选
if hits_all:
    print('\n─── 各 HIT 候选汇总 ───', flush=True)
    for cap in hits_all:
        N = cap['N']
        cands = cap.get('candidates', [])
        print(f'  HIT#{cap["n"]} N={N}: {len(cands)} 候选', flush=True)
        for ci, c in enumerate(cands):
            raw = bytes.fromhex(c.get('hex','')[:N*2])
            flds = pb_decode(raw)
            sc2  = pb_score(flds)
            print(f'    [{ci}] {c["src"]}  score={sc2}  pb={len(flds)}', flush=True)

os._exit(0)
