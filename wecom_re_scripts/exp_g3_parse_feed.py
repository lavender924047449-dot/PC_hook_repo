# exp_g3_parse_feed.py — G3: [语音] 从哪段 protobuf 字节流进 Inner proto
#
# body_slot 171024 已证明：
#   Inner proto vt 运行时 0xb065434（ASLR，文件里对不上）
#   this+8 has_bits=1，f2/f3/f4=0，this+0x10 SSO 就是裸 [语音]
#   这是新建的纯文本桩，不是清掉 media 的 voice proto
#   Inner Serialize 0x1687402 只是把已经填好的 field1 写出去
#
# capstone：0x16864d2 是同一类的 MergePartialFromCodedStream
#   field1 tag=0x0a → ReadString 0x9937640 读进 this+0x10
#   若 Parse 命中且 CIS 窗口已是 0a08[语音]，则降级发生在「组这段 bytes」的上一层
#
# 已钉死：inner = ww_richmessage.TextMessage（vtable RVA 0xaa85434，hotpatch 入口
#   Serialize 0x1687400 / Parse 0x16864d0）。默认 ctor 0x167ed90 只写空串单例。
# 8B [语音] 走 SSO，不经 0x1e917e 堆 assign；COW 脱离空串走 0x3ff450。
#
# 本脚本：
#   hook Parse 0x16864d0 / ReadString 0x9937640 / COW 0x3ff450 / append 0x1e9364
#   仅当缓冲或源串含 [语音] 才打 backtrace
#
# 用法：
#   python exp_g3_parse_feed.py            # 150s：右键语音→转发→发送 1 次
#   python exp_g3_parse_feed.py --scan     # 只扫虚表（调试）

import frida, subprocess, sys, os, json, time
from pathlib import Path
from datetime import datetime
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
SCAN_ONLY = '--scan' in sys.argv
CAPTURE_SEC = 150

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var INNER_PARSE = mod.base.add(0x16864d0);  // TextMessage MergePartial (hotpatch)
var INNER_SER   = mod.base.add(0x1687400);
var READ_STR    = mod.base.add(0x9937640);  // WireFormat ReadString
var STR_COW     = mod.base.add(0x3ff450);   // detach empty singleton → new std::string
var STR_APPEND  = mod.base.add(0x1e9364);   // append(ptr,n) may copy 8B SSO
var PRESEND     = mod.base.add(0x919ffb2);
var DO_SCAN     = __DO_SCAN__;

var U8 = [0x5b,0xe8,0xaf,0xad,0xe9,0x9f,0xb3,0x5d];

function u32pat(p) {
    var v = p.toUInt32() >>> 0;
    var s = [];
    for (var i = 0; i < 4; i++) s.push(('0' + ((v >> (i*8)) & 0xff).toString(16)).slice(-2));
    return s.join(' ');
}
function toHex(ab) {
    var a = new Uint8Array(ab), s = '';
    for (var i = 0; i < a.length; i++) s += ('0' + a[i].toString(16)).slice(-2);
    return s;
}
function findU8(ab) {
    if (!ab) return -1;
    var a = new Uint8Array(ab);
    outer: for (var i = 0; i <= a.length - 8; i++) {
        for (var j = 0; j < 8; j++) if (a[i+j] !== U8[j]) continue outer;
        return i;
    }
    return -1;
}
function describe(p) {
    try {
        var v = p.toUInt32(), b = mod.base.toUInt32();
        if (v >= b && v < b + mod.size) return 'wx+0x' + (v - b).toString(16);
        return '0x' + v.toString(16);
    } catch (e) { return '?'; }
}
function bt8() {
    var out = [];
    try {
        var fr = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 8);
        for (var i = 0; i < fr.length; i++) out.push(describe(fr[i]));
    } catch (e) {}
    return out;
}
function readStdStr(p) {
    try {
        var cap = p.add(0x14).readU32();
        var sz = p.add(0x10).readU32();
        if (sz > 0x10000) return {err: 'sz=' + sz};
        var data = (cap > 15) ? p.readPointer() : p;
        var raw = data.readByteArray(Math.min(sz, 256));
        return {sz: sz, cap: cap, hex: raw ? toHex(raw) : null, u8: raw ? findU8(raw) : -1};
    } catch (e) { return {err: e.message}; }
}

function inMod(p) {
    try {
        var v = p.toUInt32(), b = mod.base.toUInt32();
        return v >= b && v < b + mod.size;
    } catch (e) { return false; }
}

function scanVtAndCtors() {
    var ser = mod.base.add(0x1687400);  // vtable stores hotpatch entry, not +2
    var pat = u32pat(ser);
    var slotHits = [];
    // only .rdata + .data (PE layout of 5.0.10.6015); skip .text/.reloc
    var segs = [
        [0xa7fd000, 0x2328000],
        [0xcb25000, 0x2766600]
    ];
    for (var i = 0; i < segs.length; i++) {
        try {
            var ms = Memory.scanSync(mod.base.add(segs[i][0]), segs[i][1], pat);
            for (var j = 0; j < ms.length; j++) slotHits.push(ms[j].address);
        } catch (e) {}
    }
    var vtables = [];
    var seenVt = {};
    for (var k = 0; k < slotHits.length; k++) {
        var slot = slotHits[k];
        var vt = slot.sub(0x30); // SerializeWithCachedSizes = vtable+0x30 (from 0x9923cb6)
        var key = vt.toString();
        if (seenVt[key]) continue;
        seenVt[key] = 1;
        var slots = [];
        try {
            for (var s = 0; s < 16; s++) {
                var fn = vt.add(s * 4).readPointer();
                slots.push(inMod(fn) ? ('wx+0x' + fn.sub(mod.base).toString(16)) : fn.toString());
            }
        } catch (e) { continue; }
        vtables.push({
            vt: describe(vt),
            vt_raw: '0x' + vt.toUInt32().toString(16),
            slot_rva: 'wx+0x' + slot.sub(mod.base).toString(16),
            slots: slots
        });
    }

    // ctor 的 mov [reg], vt 立即数 = ImageBase+RVA，不在运行时 .text 里搜 176MB。
    // Python 拿到 vt RVA 后用 pefile 静态 xref。
    return {
        base: '0x' + mod.base.toUInt32().toString(16),
        inner_ser: describe(INNER_SER),
        slot_hits: slotHits.length,
        vtables: vtables
    };
}

if (DO_SCAN) {
    var scan = scanVtAndCtors();
    send({t: 'scan', scan: scan});
} else {
    send({t: 'scan', scan: {skipped: 1, base: '0x' + mod.base.toUInt32().toString(16)}});
}

var WIN = {tid: {}, n: 0};
Interceptor.attach(PRESEND, {
    onEnter: function () { WIN.tid[this.threadId] = 1; WIN.n++; send({t: 'pe', n: WIN.n}); },
    onLeave: function () { delete WIN.tid[this.threadId]; send({t: 'pl', n: WIN.n}); }
});

Interceptor.attach(INNER_PARSE, {
    onEnter: function (args) {
        var cis = args[0];
        var hex = null, n = 0, u8 = -1;
        try {
            var cur = cis.readPointer();
            var end = cis.add(4).readPointer();
            n = end.sub(cur).toInt32();
            if (n < 0 || n > 0x100000) n = 0;
            var take = Math.min(n, 128);
            if (take > 0) {
                var raw = cur.readByteArray(take);
                hex = toHex(raw);
                u8 = findU8(raw);
            }
        } catch (e) { hex = 'err:' + e.message; }
        if (u8 < 0) return;
        var self = this.context.ecx;
        send({
            t: 'parse',
            in_presend: !!WIN.tid[this.threadId],
            this: '0x' + self.toUInt32().toString(16),
            cis_n: n,
            cis_hex: hex,
            u8: u8,
            str_before: readStdStr(self.add(0x10)),
            bt: bt8.call(this)
        });
    }
});

Interceptor.attach(READ_STR, {
    onEnter: function (args) {
        this.cis = args[0];
        this.dst = args[1];
        this.hex = null;
        try {
            var cur = this.cis.readPointer();
            var end = this.cis.add(4).readPointer();
            var n = Math.min(Math.max(0, end.sub(cur).toInt32()), 64);
            if (n >= 8) {
                var raw = cur.readByteArray(n);
                if (findU8(raw) >= 0) this.hex = toHex(raw);
            }
        } catch (e) {}
    },
    onLeave: function () {
        if (!this.hex) return;
        var st = this.dst ? readStdStr(this.dst) : null;
        send({
            t: 'read_str',
            in_presend: !!WIN.tid[this.threadId],
            cis_hex: this.hex,
            dst: st,
            bt: bt8.call(this)
        });
    }
});

// thiscall: ecx=dest std::string*, args[0]=src std::string*
Interceptor.attach(STR_COW, {
    onEnter: function (args) {
        var src = args[0];
        var st = src ? readStdStr(src) : null;
        if (!st || st.u8 < 0) return;
        send({
            t: 'cow',
            in_presend: !!WIN.tid[this.threadId],
            src: st,
            dest: '0x' + this.context.ecx.toUInt32().toString(16),
            bt: bt8.call(this)
        });
    }
});

// thiscall: ecx=std::string*, [ebp+8]=ptr, [ebp+0xc]=n  → Frida args[0]=ptr args[1]=n
Interceptor.attach(STR_APPEND, {
    onEnter: function (args) {
        var n = 0;
        try { n = args[1].toUInt32(); } catch (e) { return; }
        if (n < 8 || n > 64) return;
        var raw = null;
        try { raw = args[0].readByteArray(n); } catch (e) { return; }
        if (!raw || findU8(raw) < 0) return;
        send({
            t: 'append',
            in_presend: !!WIN.tid[this.threadId],
            n: n,
            hex: toHex(raw),
            bt: bt8.call(this)
        });
    }
});

// ctor hooks filled from Python after scan via rpc
rpc.exports = {
    hookCtors: function (rvas) {
        var n = 0;
        for (var i = 0; i < rvas.length; i++) {
            try {
                var addr = mod.base.add(rvas[i]);
                Interceptor.attach(addr, {
                    onEnter: function () {
                        this.self = this.context.ecx;
                    },
                    onLeave: function () {
                        send({
                            t: 'ctor',
                            in_presend: !!WIN.tid[this.threadId],
                            fn: describe(this.returnAddress),
                            this: '0x' + this.self.toUInt32().toString(16),
                            vt: '0x' + this.self.readU32().toString(16),
                            bt: bt8.call(this)
                        });
                    }
                });
                n++;
            } catch (e) {}
        }
        return n;
    }
};

send({t: 'ready'});
"""

events = []
bt_count = Counter()
scan_result = {}


def on_msg(msg, data):
    global scan_result
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:500]}', flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t')
    if t == 'scan':
        scan_result = p['scan']
        if scan_result.get('skipped'):
            print(f"[+] base={scan_result.get('base')}  (skip vt scan)")
            return
        print(f"[+] base={scan_result.get('base')}  InnerSer={scan_result.get('inner_ser')}")
        print(f"    serialize-ptr hits={scan_result.get('slot_hits')}  vtables={len(scan_result.get('vtables') or [])}")
        for vt in (scan_result.get('vtables') or []):
            print(f"    VT {vt['vt']}  slot@ {vt['slot_rva']}")
            print(f"       slots={vt['slots'][:12]}")
        return
    if t == 'ready':
        print('[+] hooks: Parse 0x16864d0 + ReadString + COW 0x3ff450 + append 0x1e9364 + PreSend', flush=True)
        return
    if t == 'pe':
        print(f'\n{"="*72}\n[PRESEND #{p["n"]}] ENTER', flush=True)
        return
    if t == 'pl':
        print(f'[PRESEND #{p["n"]}] LEAVE\n{"="*72}', flush=True)
        return
    if t in ('parse', 'read_str', 'ctor', 'cow', 'append'):
        events.append(p)
        gate = 'PRE' if p.get('in_presend') else 'pre-PreSend★'
        if t == 'parse':
            print(f'  ◆ Parse [{gate}] this={p.get("this")} cis_n={p.get("cis_n")} u8@{p.get("u8")} hex={p.get("cis_hex")}', flush=True)
        elif t == 'read_str':
            print(f'  ★ ReadString [{gate}] cis={p.get("cis_hex")} dst={p.get("dst")}', flush=True)
        elif t == 'cow':
            print(f'  ★ COW [{gate}] dest={p.get("dest")} src={p.get("src")}', flush=True)
        elif t == 'append':
            print(f'  ★ append [{gate}] n={p.get("n")} hex={p.get("hex")}', flush=True)
        else:
            print(f'  ◆ ctor [{gate}] this={p.get("this")} vt={p.get("vt")} ret={p.get("fn")}', flush=True)
        for i, f in enumerate((p.get('bt') or [])[:8]):
            print(f'     bt[{i}] {f}', flush=True)
            bt_count[f] += 1
        return


def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('no pid on :9882')


def static_xref_vt(scan):
    """ctors store ImageBase+RVA of vtable; live VA = base+RVA. Xref file .text."""
    import pefile, struct
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    vts = scan.get('vtables') or []
    if not vts:
        print('[!] 无虚表，跳过静态 xref')
        return []
    base = int(scan['base'], 16)
    pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
    IB = pe.OPTIONAL_HEADER.ImageBase
    text = None
    for s in pe.sections:
        if s.Name.rstrip(b'\x00') == b'.text':
            text = s
            break
    td = text.get_data()
    tv = IB + text.VirtualAddress
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    found = []
    for vt in vts:
        live = int(vt['vt_raw'], 16)
        rva = live - base
        file_va = IB + rva
        raw = struct.pack('<I', file_va)
        print(f"[*] xref ctor imm  live={vt['vt_raw']}  rva=0x{rva:x}  file_va=0x{file_va:x}")
        off = 0
        n = 0
        while n < 20:
            i = td.find(raw, off)
            if i < 0:
                break
            start = max(0, i - 8)
            ins = None
            for d in md.disasm(td[start:i + 6], tv + start):
                if d.address <= tv + i < d.address + d.size:
                    ins = d
                    break
            rva_i = text.VirtualAddress + i
            line = f'wx+0x{rva_i:x}'
            if ins:
                line += f'  {ins.mnemonic} {ins.op_str}'
            print(f'    {line}')
            found.append({'rva': rva_i, 'text': line, 'vt_rva': rva})
            n += 1
            off = i + 1
        if n == 0:
            print('    (none in .text)')
    return found


def main():
    pid = get_pid()
    print(f'[*] PID={pid}  scan_only={SCAN_ONLY}')
    sess = frida.get_local_device().attach(pid)
    js = JS.replace('__DO_SCAN__', 'true' if SCAN_ONLY else 'false')
    sc = sess.create_script(js)
    sc.on('message', on_msg)
    print('[*] attaching…', flush=True)
    sc.load()
    time.sleep(0.5)

    xrefs = []
    if SCAN_ONLY and scan_result and not scan_result.get('skipped'):
        try:
            xrefs = static_xref_vt(scan_result)
        except Exception as e:
            print(f'[!] static xref failed: {e}')

    (OUT / f'g3parse_{ts}_scan.json').write_text(
        json.dumps({'scan': scan_result, 'ctor_xrefs': xrefs}, ensure_ascii=False, indent=2),
        encoding='utf-8')
    print(f'    扫描产物 g3parse_{ts}_scan.json')

    if SCAN_ONLY:
        try:
            sc.unload(); sess.detach()
        except Exception:
            pass
        os._exit(0)

    print(f'\n{"="*72}\n★★★ {CAPTURE_SEC}s：右键已同步语音 → 转发 → 发送 1 次 ★★★')
    print('  重点：COW/Parse 带 [语音] 的 backtrace（谁先把占位符写进 TextMessage）\n'
          f'{"="*72}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try:
        sc.unload(); sess.detach()
    except Exception:
        pass
    print(f'\n[+] 收工  events={len(events)}')
    if bt_count:
        print('★ backtrace 帧频次:')
        for k, c in bt_count.most_common(15):
            print(f'    {c:3d}  {k}')
    (OUT / f'g3parse_{ts}_report.json').write_text(
        json.dumps({'scan': scan_result, 'events': events, 'bt': dict(bt_count)},
                   ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'    产物 g3parse_{ts}_report.json')
    os._exit(0)


if __name__ == '__main__':
    main()
