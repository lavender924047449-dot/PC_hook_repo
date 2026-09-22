# exp_g3_downgrade_probe.py v2 — 抓 "voice → [语音]" 降级点
#
# v1 作废原因（2026-09-14 16:00 实测）：
#   Frida 17 无 Module.findExportByName → TypeError: not a function
#   memcpy hook 从未装上；PreSend 两次是真的，0 HIT 无证据价值。
#   且 [语音] UTF-8 = 8B，MSVC SSO (cap=15) 赋值常常根本不走 memcpy。
#
# v2 策略（不依赖 memcpy 作为主路径）：
#   A. PreSend onEnter：扫 args[1] 2KB + 一层指针 256B，找 UTF-8 / UTF-16 [语音]
#      → 若 ENTER 已有字符串：降级在 PreSend 之前
#      → 若 LEAVE 才有：降级在 PreSend 内部
#      → 若全程没有：字符串只在 SER 的 wire 缓冲里出现（ConstructProto 阶段）
#   B. attach 后只读扫 WXWork.exe 映像：运行时解密后的 [语音] 字面量
#      → 找到 VA 后在 .text 扫 4B little-endian immediate = xref（v1 静态扫盘 0 hit 是因为加密）
#   C. memcpy 仅作辅路：Frida 17 兼容 + ucrtbase，TLS 门控，n<=64，双编码
#
# 用法（与 v1 相同）：
#   python exp_g3_downgrade_probe.py
#   150s 内：右键已同步语音 → 转发 → 任意联系人 → 发送

import frida, subprocess, sys, os, json, struct
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 150
PRESEND_RVA = 0x919ffb2

UTF8_HEX  = '5be8afade99fb35d'          # [语音] UTF-8
UTF16_HEX = '5b00ed8bf3975d00'          # [语音] UTF-16LE
UTF8_PAT  = '5b e8 af ad e9 9f b3 5d'
UTF16_PAT = '5b 00 ed 8b f3 97 5d 00'

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(__PRESEND_RVA__);
var UTF8 = [0x5b,0xe8,0xaf,0xad,0xe9,0x9f,0xb3,0x5d];
var UTF16 = [0x5b,0x00,0xed,0x8b,0xf3,0x97,0x5d,0x00];

function safeBytes(a, sz) {
    try {
        var p = (typeof a === 'number') ? ptr(a) : a;
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
function findPat(ab, pat) {
    if (!ab) return -1;
    var a = new Uint8Array(ab);
    outer: for (var i=0;i<=a.length-pat.length;i++) {
        for (var j=0;j<pat.length;j++) if (a[i+j]!==pat[j]) continue outer;
        return i;
    }
    return -1;
}
function describe(p) {
    try {
        var v = p.toUInt32();
        var b = mod.base.toUInt32();
        if (v>=b && v<b+mod.size) return 'wx+0x'+(v-b).toString(16);
        return '0x'+v.toString(16);
    } catch(e) { return '?'; }
}
function resolveExp(modName, expName) {
    try {
        var m = Process.getModuleByName(modName);
        if (m && typeof m.findExportByName === 'function') {
            var p = m.findExportByName(expName);
            if (p && !p.isNull()) return p;
        }
        if (m && typeof m.getExportByName === 'function') {
            try { return m.getExportByName(expName); } catch(e) {}
        }
    } catch(e) {}
    try {
        if (typeof Module.getExportByName === 'function')
            return Module.getExportByName(modName, expName);
    } catch(e) {}
    return null;
}

var WIN = {tid:{}, cnt:0};
var HIT_CNT = 0;
var CALLER_STATS = {};
var SCAN_DONE = false;

Interceptor.attach(PRESEND, {
    onEnter: function(args) {
        WIN.tid[this.threadId] = 1;
        WIN.cnt++;
        this._sn = WIN.cnt;
        var a1 = args[1].toUInt32();
        this._a1 = a1;
        var raw = safeBytes(a1, 2048);
        var hex = raw ? toHex(raw) : null;
        var u8 = hex ? findPat(raw, UTF8) : -1;
        var u16 = hex ? findPat(raw, UTF16) : -1;
        var chased = [];
        if (raw) {
            var d = new Uint8Array(raw);
            var seen = {};
            for (var i=0;i+3<Math.min(d.length,512) && chased.length<12;i+=4) {
                var pv = (d[i]|(d[i+1]<<8)|(d[i+2]<<16)|(d[i+3]<<24))>>>0;
                if (pv<0x10000 || pv>0x7F000000 || seen[pv]) continue;
                seen[pv]=1;
                var ch = safeBytes(pv, 256);
                if (!ch) continue;
                var o8 = findPat(ch, UTF8), o16 = findPat(ch, UTF16);
                if (o8>=0 || o16>=0) {
                    chased.push({off:i, ptr:'0x'+pv.toString(16), u8:o8, u16:o16,
                                 head:toHex(ch).slice(0,64)});
                }
            }
        }
        send({t:'presend_enter', sn:this._sn, arg1:'0x'+a1.toString(16),
              u8:u8, u16:u16, chased:chased, hex:hex});
    },
    onLeave: function(rv) {
        var a1 = this._a1;
        var raw = safeBytes(a1, 2048);
        var u8 = raw ? findPat(raw, UTF8) : -1;
        var u16 = raw ? findPat(raw, UTF16) : -1;
        delete WIN.tid[this.threadId];
        send({t:'presend_leave', sn:this._sn, retval:'0x'+rv.toUInt32().toString(16),
              u8:u8, u16:u16, hex: raw ? toHex(raw) : null,
              memcpy_hits: HIT_CNT});
    }
});

function hookCopy(addr, name) {
    if (!addr || addr.isNull()) return false;
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                if (!WIN.tid[this.threadId]) return;
                var n = 0;
                try { n = args[2].toUInt32(); } catch(e) { return; }
                if (n<8 || n>64) return;
                var src = args[1];
                var raw = safeBytes(src, Math.min(n, 64));
                if (!raw) return;
                var o8 = findPat(raw, UTF8), o16 = findPat(raw, UTF16);
                if (o8<0 && o16<0) return;
                HIT_CNT++;
                var ra = this.returnAddress;
                var rav = ra.toUInt32();
                var b = mod.base.toUInt32();
                var crva = (rav>=b && rav<b+mod.size) ? (rav-b) : null;
                var key = crva!==null ? '0x'+crva.toString(16) : 'ext';
                CALLER_STATS[key] = (CALLER_STATS[key]||0)+1;
                var bt = [];
                try {
                    var frames = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,6);
                    for (var i=0;i<frames.length;i++) bt.push(describe(frames[i]));
                } catch(e) {}
                send({t:'memcpy_hit', hook:name, n:n, enc:(o8>=0?'utf8':'utf16'),
                      off:(o8>=0?o8:o16), dst:describe(args[0]), src:describe(src),
                      caller_rva: crva!==null ? '0x'+crva.toString(16) : null,
                      bt:bt, src_head:toHex(raw)});
            }
        });
        return true;
    } catch(e) {
        send({t:'hook_err', name:name, err:e.message});
        return false;
    }
}

var memcpy_hooked = [];
var CRT = ['ucrtbase.dll','msvcrt.dll','vcruntime140.dll','ntdll.dll'];
var EXPS = {
    'ucrtbase.dll': ['memcpy','memmove'],
    'msvcrt.dll': ['memcpy','memmove'],
    'vcruntime140.dll': ['memcpy','memmove'],
    'ntdll.dll': ['memmove','memcpy','RtlMoveMemory']
};
for (var i=0;i<CRT.length;i++) {
    var names = EXPS[CRT[i]] || [];
    for (var j=0;j<names.length;j++) {
        var p = resolveExp(CRT[i], names[j]);
        if (p && hookCopy(p, CRT[i]+'!'+names[j])) memcpy_hooked.push(CRT[i]+'!'+names[j]);
    }
}

rpc.exports.scanMod = function() {
    var out = {utf8:[], utf16:[]};
    var chunk = 0x400000;
    var base = mod.base;
    var size = mod.size;
    for (var off=0; off<size; off+=chunk) {
        var n = Math.min(chunk, size-off);
        try {
            var h8 = Memory.scanSync(base.add(off), n, '5b e8 af ad e9 9f b3 5d');
            for (var i=0;i<h8.length && out.utf8.length<20;i++)
                out.utf8.push('0x'+h8[i].address.toUInt32().toString(16));
        } catch(e) {}
        try {
            var h16 = Memory.scanSync(base.add(off), n, '5b 00 ed 8b f3 97 5d 00');
            for (var i=0;i<h16.length && out.utf16.length<20;i++)
                out.utf16.push('0x'+h16[i].address.toUInt32().toString(16));
        } catch(e) {}
        if (out.utf8.length>=20 && out.utf16.length>=20) break;
    }
    return out;
};

rpc.exports.xrefVa = function(vaNum) {
    var needle = [];
    var v = vaNum >>> 0;
    needle.push(v & 0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff);
    var pat = needle.map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ');
    var hits = [];
    var chunk = 0x400000;
    for (var off=0; off<mod.size && hits.length<30; off+=chunk) {
        var n = Math.min(chunk, mod.size-off);
        try {
            var r = Memory.scanSync(mod.base.add(off), n, pat);
            for (var i=0;i<r.length && hits.length<30;i++) {
                var abs = r[i].address.toUInt32();
                hits.push('0x'+(abs - mod.base.toUInt32()).toString(16));
            }
        } catch(e) {}
    }
    return hits;
};

rpc.exports.stats = function() {
    return {hits:HIT_CNT, callers:CALLER_STATS, presend:WIN.cnt,
            memcpy_hooked: memcpy_hooked};
};

send({t:'ready', memcpy_hooked: memcpy_hooked});
"""

hits_memcpy = []
presends = []
caller_agg = Counter()

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:500]}', flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']; t = p.get('t')
    if t == 'ready':
        print(f'[+] memcpy hooks: {p.get("memcpy_hooked") or "(none)"}', flush=True)
        return
    if t == 'hook_err':
        print(f'[!] hook_err {p["name"]}: {p["err"]}', flush=True)
        return
    if t == 'presend_enter':
        tag = []
        if p['u8'] >= 0: tag.append(f'UTF8@+0x{p["u8"]:x}')
        if p['u16'] >= 0: tag.append(f'UTF16@+0x{p["u16"]:x}')
        if p.get('chased'): tag.append(f'L1x{len(p["chased"])}')
        mark = ' ★ [语音] ' + ' '.join(tag) if tag else '  (args[1] 无 [语音])'
        print(f'\n{"="*72}\n[PRESEND #{p["sn"]}] ENTER  arg1={p["arg1"]}{mark}', flush=True)
        if p.get('chased'):
            for c in p['chased']:
                print(f'    L1 +0x{c["off"]:02x} -> {c["ptr"]}  u8={c["u8"]} u16={c["u16"]}', flush=True)
        if p.get('hex'):
            fn = OUT_DIR / f'g3exp_{ts}_sn{p["sn"]}_enter.bin'
            fn.write_bytes(bytes.fromhex(p['hex']))
        presends.append({'phase':'enter', **{k:v for k,v in p.items() if k!='hex'}})
        return
    if t == 'presend_leave':
        tag = []
        if p['u8'] >= 0: tag.append(f'UTF8@+0x{p["u8"]:x}')
        if p['u16'] >= 0: tag.append(f'UTF16@+0x{p["u16"]:x}')
        mark = ' ★ [语音] ' + ' '.join(tag) if tag else '  (仍无)'
        print(f'[PRESEND #{p["sn"]}] LEAVE  retval={p["retval"]}  memcpy_hits={p.get("memcpy_hits")}{mark}\n{"="*72}', flush=True)
        if p.get('hex'):
            fn = OUT_DIR / f'g3exp_{ts}_sn{p["sn"]}_leave.bin'
            fn.write_bytes(bytes.fromhex(p['hex']))
        presends.append({'phase':'leave', **{k:v for k,v in p.items() if k!='hex'}})
        return
    if t == 'memcpy_hit':
        hits_memcpy.append(p)
        caller_agg[p.get('caller_rva') or 'ext'] += 1
        print(f'  ★ memcpy {p["hook"]} n={p["n"]} {p["enc"]} caller={p.get("caller_rva")} src={p["src"]}', flush=True)
        for i, f in enumerate(p.get('bt', [])[:4]):
            print(f'     bt[{i}] {f}', flush=True)
        return

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

def main():
    pid = get_pid(); print(f'[*] PID={pid}  (v2: scan args[1] + runtime literal + memcpy aux)')
    js = JS.replace('__PRESEND_RVA__', str(PRESEND_RVA))
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()

    print('[*] 扫 WXWork.exe 映像里运行时解密的 [语音] 字面量（只读，约 10-20s）…', flush=True)
    lit = {'utf8': [], 'utf16': []}
    try:
        lit = sc.exports_sync.scan_mod()
    except Exception as e:
        print(f'[!] scan_mod failed: {e}', flush=True)
    print(f'    UTF-8  hits: {lit.get("utf8")}', flush=True)
    print(f'    UTF-16 hits: {lit.get("utf16")}', flush=True)

    xrefs = {}
    for enc, vas in (('utf8', lit.get('utf8') or []), ('utf16', lit.get('utf16') or [])):
        for va_s in vas[:6]:
            va = int(va_s, 16)
            try:
                xr = sc.exports_sync.xref_va(va)
            except Exception as e:
                xr = [f'err:{e}']
            xrefs[f'{enc}:{va_s}'] = xr
            print(f'    xref {enc} {va_s} → {xr[:12]}{"…" if len(xr)>12 else ""}', flush=True)

    import time
    print(f'\n{"="*72}')
    print(f'★★★  你有 {CAPTURE_SEC}s ★★★')
    print(f'  右键已同步语音气泡 → 转发 → 任意联系人 → 发送（1 次）')
    print(f'  看 PRESEND ENTER 是否已经带 [语音]（之前 vs 之中 vs SER 才出现）')
    print(f'{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)

    try:
        stats = sc.exports_sync.stats()
    except Exception:
        stats = {}
    try:
        sc.unload(); sess.detach()
    except Exception:
        pass

    print(f'\n{"="*72}\n[+] 收工')
    print(f'    PreSend 事件(enter 记录) = {sum(1 for x in presends if x.get("phase")=="enter")}')
    print(f'    memcpy HIT = {len(hits_memcpy)}  hooked={stats.get("memcpy_hooked")}')
    print(f'    literal UTF-8  = {lit.get("utf8")}')
    print(f'    literal UTF-16 = {lit.get("utf16")}')
    if caller_agg:
        print('    memcpy callers:')
        for rva, c in caller_agg.most_common(15):
            print(f'      {rva}  x{c}')

    # 判定
    enters = [x for x in presends if x.get('phase')=='enter']
    leaves = [x for x in presends if x.get('phase')=='leave']
    def has_voice(rec):
        return (rec.get('u8',-1)>=0) or (rec.get('u16',-1)>=0) or rec.get('chased')
    print('\n★ 判定:')
    if not enters:
        print('    未捕获 PreSend — 确认是否真的点了转发发送')
    elif any(has_voice(x) for x in enters):
        print('    ENTER 已有 [语音] → 降级在 PreSend 之前。看 literal xref 追调用方。')
    elif any(has_voice(x) for x in leaves):
        print('    ENTER 无 / LEAVE 有 → 降级在 PreSend 内部。')
    else:
        print('    args[1] 全程无 [语音] → 字符串只在 ConstructProto/SER wire 里出现。')
    if not lit.get('utf8') and not lit.get('utf16'):
        print('    映像内仍无明文 [语音]（仍加密或运行时拼接 [ + 语音 + ]）。')
    elif any(xrefs.get(k) for k in xrefs):
        print('    已拿到运行时字面量 xref — 下轮直接 hook 这些 RVA。')

    report = {
        'ts': ts, 'lit': lit, 'xrefs': xrefs,
        'presends': presends, 'memcpy_hits': hits_memcpy,
        'memcpy_hooked': stats.get('memcpy_hooked'),
        'callers': dict(caller_agg),
    }
    (OUT_DIR / f'g3exp_{ts}_report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'\n    产物：g3exp_{ts}_report.json  +  g3exp_{ts}_sn*_enter/leave.bin')
    os._exit(0)

if __name__ == '__main__':
    main()
