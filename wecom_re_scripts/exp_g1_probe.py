# exp_g1_probe.py — G1 (recv voice MessageObject → PreSend arg1) 三档快速验证实验
#
# 目的（30-60 min 内二值判定 G1 是否走得通）：
#   档 A (DRY)   : 只 dump args[1] + 追指针；不改任何字节。建 baseline。
#   档 B (MIN)   : 仅把 args[1]+0x12c 与 +0x130 疑似 msgtype dword 改成候选 voice 值。
#                  用来快速二分 msgtype 枚举 & 观察 PreSend 内部 filter。
#   档 C (INJECT): 把 Step 1 recv-side voice MessageObject dump 里
#                  提取的 file_id / aeskey / duration 三字段字节
#                  memcpy 到 args[1] 内对应 slot（offset 由环境变量控制，可迭代）。
#
# 环境变量：
#   G1_MODE       = DRY | MIN | INJECT           （默认 DRY）
#   G1_MSGTYPE    = 34                            （B/C 档用；候选：34/2/9/45/62/74）
#   G1_MSGTYPE_OFF= 0x130                         （patch msgtype dword 的偏移，默认 +0x130；也可试 0x12c）
#   G1_RECV_BIN   = <path to recv voice arg0 bin> （C 档用；Step 1 落盘的那份）
#   G1_INJECT_MAP = "off=hex,off=hex,..."         （C 档用；args[1] 内目标偏移 → 覆写的字节 hex）
#                    比如 "0x160=<32B hex file_id>,0x1a0=<32B aeskey>,0x1c0=04000000"
#   G1_PROBE_TAG  = "PROBE-G1"                     （只在此 tag 消息触发时 patch，避免误伤别的发送）
#
# 用法：
#   # 档 A（DRY 只观测）
#   $env:G1_MODE="DRY"; python exp_g1_probe.py
#
#   # 档 B（msgtype patch）
#   $env:G1_MODE="MIN"; $env:G1_MSGTYPE="34"; $env:G1_MSGTYPE_OFF="0x130"; python exp_g1_probe.py
#
#   # 档 C（字段注入）
#   $env:G1_MODE="INJECT"; $env:G1_MSGTYPE="34"; \
#     $env:G1_INJECT_MAP="0x180=<hex>,0x1c0=04000000"; python exp_g1_probe.py
#
# 观测（都自动落盘 & stdout）：
#   1. PreSend 是否 return 非 0（成功）
#   2. SER (0x9f042a0) 在 PreSend TLS 窗口内的 hit 数
#   3. onLeave 时再读 args[1] 前 2KB → diff before/after
#   4. 参考 hook_wire_sample.py 采样 outbound wire body（另开一次跑）
#
# 判定表见 REVERSE_ENGINEERING_HANDOFF.md 下一轮更新。

import frida, subprocess, sys, os, json, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 120

# ── 目标 ──
PRESEND_RVA = 0x919ffb2
V_SER       = 0x09f042a0
OUTER_VT    = 0xb0610c0  # 主 SER 触发的顶层 wrapper vt

# ── 环境变量 ──
MODE       = os.environ.get('G1_MODE', 'DRY').upper()
MSGTYPE_NEW= int(os.environ.get('G1_MSGTYPE', '34'))
MSGTYPE_OFF= int(os.environ.get('G1_MSGTYPE_OFF', '0x130'), 0)
PROBE_TAG  = os.environ.get('G1_PROBE_TAG', 'PROBE-G1').encode('utf-8')
INJECT_MAP_RAW = os.environ.get('G1_INJECT_MAP', '')

if MODE not in ('DRY', 'MIN', 'INJECT'):
    print(f'[!] G1_MODE={MODE} 非法，需为 DRY/MIN/INJECT', flush=True); sys.exit(1)

# 解析 INJECT_MAP："off=hex,off=hex"
INJECT_MAP = []  # list of (off_int, bytes)
if MODE == 'INJECT' and INJECT_MAP_RAW:
    for pair in INJECT_MAP_RAW.split(','):
        pair = pair.strip()
        if not pair: continue
        m = re.match(r'^(0x[0-9a-fA-F]+|\d+)=([0-9a-fA-F]+)$', pair)
        if not m:
            print(f'[!] INJECT_MAP 项非法: {pair!r}', flush=True); sys.exit(1)
        off = int(m.group(1), 0)
        payload = bytes.fromhex(m.group(2))
        INJECT_MAP.append((off, payload))
    print(f'[*] INJECT_MAP: {len(INJECT_MAP)} 条')
    for off, p in INJECT_MAP:
        print(f'    +0x{off:03x}  <-  {p.hex()[:64]}{"..." if len(p)>32 else ""}  ({len(p)}B)')

print(f'[*] G1_MODE={MODE}')
if MODE in ('MIN', 'INJECT'):
    print(f'[*] msgtype patch: args[1]+0x{MSGTYPE_OFF:03x} <- {MSGTYPE_NEW}')
print(f'[*] PROBE_TAG={PROBE_TAG!r} （只在 args[1] 附近 ASCII 里出现此 tag 时才 patch）')
print(f'[*] output ts={ts}')

# ── Frida JS ──
JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(__PRESEND_RVA__);
var V_SER   = ptr(__V_SER__);
var OUTER_VT= __OUTER_VT__;
var MODE    = "__MODE__";
var MSGTYPE_NEW = __MSGTYPE_NEW__;
var MSGTYPE_OFF = __MSGTYPE_OFF__;
var PROBE_TAG   = __PROBE_TAG_JS__;   // hex string
var INJECT_MAP  = __INJECT_MAP_JS__;  // [[off, "hexpayload"], ...]

function safeBytes(a, sz) {
    try { var p = (typeof a === 'number') ? ptr(a) : a;
        var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s='';
    for (var i=0;i<a.length;i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function hexToBytes(h) {
    var out = new Uint8Array(h.length/2);
    for (var i=0;i<out.length;i++) out[i] = parseInt(h.substr(i*2,2),16);
    return out;
}
function bytesContains(hay_hex, needle_hex) {
    return hay_hex.indexOf(needle_hex) >= 0;
}

var WIN = {tid:{}, cnt:0};
var SER_HITS = 0;
var LAST_PATCH = null;

Interceptor.attach(PRESEND, {
    onEnter: function(args) {
        WIN.tid[this.threadId] = 1;
        WIN.cnt++;
        SER_HITS = 0;
        var arg1 = args[1];
        var arg1_addr = arg1.toUInt32();
        this._arg1_addr = arg1_addr;
        this._sn = WIN.cnt;

        // dump before
        var raw_before = safeBytes(arg1_addr, 2048);
        var hex_before = raw_before ? toHex(raw_before) : null;

        // 判定是否是 PROBE 消息（args[1] 前 2KB 里含 PROBE_TAG 字节）
        var is_probe = hex_before && bytesContains(hex_before, PROBE_TAG);

        send({t:'presend_enter', sn:this._sn, arg1:'0x'+arg1_addr.toString(16),
              is_probe: is_probe, hex_before: hex_before});

        // 只在 PROBE 消息上打 patch
        var patched = [];
        var patch_errs = [];
        if (is_probe && MODE !== 'DRY') {
            // 1) msgtype dword patch
            try {
                var addr = ptr(arg1_addr + MSGTYPE_OFF);
                var orig = addr.readU32();
                Memory.protect(addr, 4, 'rwx');
                addr.writeU32(MSGTYPE_NEW);
                patched.push({op:'msgtype', off:MSGTYPE_OFF, orig:orig, newv:MSGTYPE_NEW});
            } catch(e) { patch_errs.push('msgtype: '+e.message); }

            // 2) INJECT map (仅 C 档)
            if (MODE === 'INJECT') {
                for (var i=0; i<INJECT_MAP.length; i++) {
                    var off = INJECT_MAP[i][0];
                    var payload_hex = INJECT_MAP[i][1];
                    try {
                        var bs = hexToBytes(payload_hex);
                        var a = ptr(arg1_addr + off);
                        Memory.protect(a, bs.length, 'rwx');
                        // 存下 orig，方便回读 diff
                        var orig_bs = a.readByteArray(bs.length);
                        for (var j=0; j<bs.length; j++) a.add(j).writeU8(bs[j]);
                        patched.push({op:'inject', off:off, len:bs.length,
                                      orig:toHex(orig_bs), newv:payload_hex});
                    } catch(e) { patch_errs.push('inject +0x'+off.toString(16)+': '+e.message); }
                }
            }
        }
        LAST_PATCH = {sn:this._sn, is_probe:is_probe, mode:MODE,
                      patched: patched, errs: patch_errs};
        send({t:'presend_patch', sn:this._sn, is_probe:is_probe, patched:patched, errs:patch_errs});
    },
    onLeave: function(rv) {
        delete WIN.tid[this.threadId];
        var arg1_addr = this._arg1_addr;
        var raw_after = safeBytes(arg1_addr, 2048);
        send({t:'presend_leave', sn:this._sn,
              retval:'0x'+rv.toUInt32().toString(16),
              ser_hits: SER_HITS,
              hex_after: raw_after ? toHex(raw_after) : null});
    }
});

Interceptor.attach(V_SER, {
    onEnter: function(args) {
        if (!WIN.tid[this.threadId]) return;
        SER_HITS++;
        var this_v = this.context.ecx.toUInt32();
        var raw = safeBytes(this_v, 32);
        if (!raw) return;
        var a = new Uint8Array(raw);
        var vt = (a[0]|(a[1]<<8)|(a[2]<<16)|(a[3]<<24)) >>> 0;
        var arg0_v = args[0].toUInt32();
        var body = safeBytes(arg0_v, 256);
        send({t:'ser', n:SER_HITS, vt:'0x'+vt.toString(16),
              this_addr:'0x'+this_v.toString(16), arg0_addr:'0x'+arg0_v.toString(16),
              body_head: body ? toHex(body) : null});
    }
});

send({t:'ready'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

REPORTS = []
PROBE_HITS = 0

def hex_diff(a, b, max_show=20):
    """快速 diff 两个 hex 字符串，返回差异 [(byte_off, a_byte, b_byte)]。"""
    diffs = []
    m = min(len(a), len(b))
    for i in range(0, m, 2):
        if a[i:i+2] != b[i:i+2]:
            diffs.append((i//2, a[i:i+2], b[i:i+2]))
            if len(diffs) >= max_show: break
    return diffs

def on_msg(msg, data):
    global PROBE_HITS
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')

    if t == 'ready':
        print('[+] G1 probe hook ARMED', flush=True); return

    if t == 'presend_enter':
        marker = '★PROBE★' if p['is_probe'] else '·normal·'
        print(f'\n{"="*72}\n[PRESEND #{p["sn"]}] ENTER  arg1={p["arg1"]}  {marker}', flush=True)
        if p['is_probe']:
            PROBE_HITS += 1
        # 落盘 before
        if p.get('hex_before'):
            fn = OUT_DIR / f'g1exp_{ts}_sn{p["sn"]}_{"probe" if p["is_probe"] else "norm"}_before.bin'
            fn.write_bytes(bytes.fromhex(p['hex_before']))
        return

    if t == 'presend_patch':
        if not p['is_probe']:
            return
        if p['patched']:
            print(f'  ▶ patched {len(p["patched"])} 处:', flush=True)
            for pp in p['patched']:
                if pp['op'] == 'msgtype':
                    print(f'    · msgtype  args[1]+0x{pp["off"]:03x}  {pp["orig"]} → {pp["newv"]}', flush=True)
                else:
                    print(f'    · inject   args[1]+0x{pp["off"]:03x}  ({pp["len"]}B)  '
                          f'{pp["orig"][:32]}... → {pp["newv"][:32]}...', flush=True)
        if p['errs']:
            for e in p['errs']:
                print(f'    ★ patch err: {e}', flush=True)
        return

    if t == 'presend_leave':
        print(f'[PRESEND #{p["sn"]}] LEAVE  retval={p["retval"]}  SER hits={p["ser_hits"]}\n{"="*72}', flush=True)
        # 落盘 after
        if p.get('hex_after'):
            fn = OUT_DIR / f'g1exp_{ts}_sn{p["sn"]}_after.bin'
            fn.write_bytes(bytes.fromhex(p['hex_after']))
        REPORTS.append({'sn': p['sn'], 'retval': p['retval'], 'ser_hits': p['ser_hits']})
        return

    if t == 'ser':
        vt = p['vt']
        # 只详细打印非常见 vt（可能是 voice 新 vt）
        tag = ''
        if int(vt, 16) == 0xb0610c0: tag = 'outer'
        elif int(vt, 16) == 0xb06c9b8: tag = 'sub-A'
        elif int(vt, 16) == 0xb0656a8: tag = 'body'
        elif int(vt, 16) == 0xb0901ac: tag = 'extra'
        elif int(vt, 16) in (0xb9c0620, 0xb9c0244, 0xba8edc8): tag = '★★★ RECV-VOICE-VT ★★★'
        else: tag = 'NEW?'
        print(f'  ▶ SER#{p["n"]:02d}  vt={vt}  [{tag}]  this={p["this_addr"]}  arg0={p["arg0_addr"]}', flush=True)
        if tag == 'NEW?' or 'RECV' in tag:
            print(f'      body_head: {p.get("body_head","")[:96]}', flush=True)
        return

def main():
    pid = get_pid(); print(f'[*] PID={pid}')

    # 把 python 值嵌入到 JS 里
    inject_map_js = '[' + ','.join(
        f'[{off},"{payload.hex()}"]' for off, payload in INJECT_MAP
    ) + ']'
    probe_tag_js = '"' + PROBE_TAG.hex() + '"'

    js = (JS_TPL
        .replace('__PRESEND_RVA__', str(PRESEND_RVA))
        .replace('__V_SER__',       str(V_SER))
        .replace('__OUTER_VT__',    str(OUTER_VT))
        .replace('__MODE__',        MODE)
        .replace('__MSGTYPE_NEW__', str(MSGTYPE_NEW))
        .replace('__MSGTYPE_OFF__', str(MSGTYPE_OFF))
        .replace('__PROBE_TAG_JS__', probe_tag_js)
        .replace('__INJECT_MAP_JS__', inject_map_js)
    )
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}')
    print(f'★★★  你有 {CAPTURE_SEC}s ★★★')
    print(f'  · MODE={MODE}   probe_tag={PROBE_TAG.decode()!r}')
    print(f'  · 从 PC 企微给 FTA 发一条【文字消息】，内容【包含 "{PROBE_TAG.decode()}" 字样】')
    print(f'    (例："{PROBE_TAG.decode()}-001-B34" 这样的)')
    print(f'  · 只有包含这个 tag 的消息会被 patch，其它消息保持原样，避免误伤')
    print(f'  · 之后：观察 FTA 是否收到；小号需另开 hook_wire_sample.py 抓 wire')
    print(f'{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 收工. PreSend 总触发 = {len(REPORTS)}. probe 触发 = {PROBE_HITS}')
    print(f'    reports: {json.dumps(REPORTS, ensure_ascii=False)}')
    (OUT_DIR / f'g1exp_{ts}_report.json').write_text(
        json.dumps({'mode':MODE, 'msgtype_new':MSGTYPE_NEW, 'msgtype_off':MSGTYPE_OFF,
                    'probe_hits':PROBE_HITS, 'reports':REPORTS, 'inject_map':[
                        {'off':off, 'payload_hex':p.hex()} for off,p in INJECT_MAP]},
                   ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'    产物：g1exp_{ts}_sn*_before.bin / _after.bin / _report.json')
    os._exit(0)

if __name__ == '__main__':
    main()
