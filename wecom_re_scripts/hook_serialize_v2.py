# hook_serialize_v2.py — 收关：onLeave 时解 args[0] std::string* → dump 序列化 proto 明文
#
# 已知（§47.13 反汇编确认）：
#   PTR_A/PTR_B 都是标准 MSVC __thiscall MessageLite 派生方法，
#     ecx=this (Message*), edi=[ebp+8]=args[0]=std::string* out
#   MSVC std::string layout: [char[16] 或 char*][size:u32 @+0x10][cap:u32 @+0x14]
#     SSO 模式 cap<=15：前 16B 直接是字符
#     heap 模式 cap>15：+0x00 = heap ptr, 后跟 size 字节
#
# 策略：
#   1. TLS 门控在 PreSend 窗口内
#   2. onEnter：拿 ecx（this）和 args[0]（预备的 out buffer），只记地址
#   3. onLeave：
#      a. 读 args[0]+0x10 得 size, +0x14 得 cap
#      b. 若 cap > 15：读 [args[0]+0x00] 作 char*，deref 后读 `size` 字节 = proto 输出
#      c. 若 cap <=15：读 args[0]+0x00 起 size 字节 = inline SSO 内容
#      d. 顺便读 ecx 前 128B 看类型（前 4 字节 vtable ptr → 定位类）
#   4. 过滤：ecx 或 args[0] 相关内存里出现 FILEASSIST 才落盘（真消息）

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90
PTR_A = 0x09f042a0
PTR_B = 0x09f03c40
MAX_HITS = 40

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(0x919ffb2);
var PTR_A = ptr('__PTRA__');
var PTR_B = ptr('__PTRB__');
var MAX = __MAX__;

function safeBytes(a, sz) {
    try { var p = (typeof a === 'object') ? a : ptr(a);
        var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function safeU32(a, off) {
    try { return ptr(a).add(off).readU32(); } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s='';
    for (var i=0; i<a.length; i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function hasFA(hex) { return hex.indexOf('46494c45415353495354') !== -1; }

// 读 MSVC std::string，返回 {size, cap, mode, data_hex}
function readStdString(str_va) {
    var size = safeU32(str_va, 0x10);
    var cap  = safeU32(str_va, 0x14);
    if (size === null || cap === null) return null;
    if (cap > 0x100000 || size > cap + 32) return null;   // 明显不是 std::string
    var mode, data_hex, data_addr;
    if (cap <= 15) {
        var raw = safeBytes(str_va, Math.min(size + 1, 16));
        if (!raw) return null;
        mode = 'sso'; data_hex = toHex(raw).slice(0, size*2); data_addr = str_va.toString();
    } else {
        var ptr_val = safeU32(str_va, 0x00);
        if (ptr_val === null) return null;
        var raw = safeBytes(ptr_val, Math.min(size, 4096));
        if (!raw) return null;
        mode = 'heap'; data_hex = toHex(raw); data_addr = '0x'+ptr_val.toString(16);
    }
    return {size:size, cap:cap, mode:mode, data_addr:data_addr, data_hex:data_hex};
}

// 读 vtable
function readVtable(this_va) {
    var vptr = safeU32(this_va, 0);
    if (vptr === null) return null;
    var tbl = [];
    for (var i=0; i<20; i++) {
        var fn = safeU32(vptr, i*4);
        if (fn === null) break;
        tbl.push('0x'+fn.toString(16));
    }
    return {vptr: '0x'+vptr.toString(16), slots: tbl};
}

var WIN = {tid: {}};
var hitA = 0, hitB = 0;

Interceptor.attach(PRESEND, {
    onEnter: function(a) { WIN.tid[this.threadId] = 1; },
    onLeave: function(r) { delete WIN.tid[this.threadId]; }
});

function attach(addr, tag) {
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                if (!WIN.tid[this.threadId]) return;
                if ((tag==='A' && hitA >= MAX) || (tag==='B' && hitB >= MAX)) return;
                this._this_va = this.context.ecx.toUInt32();   // MSVC __thiscall
                this._out_va  = args[0].toUInt32();            // std::string* out
                this._skip = false;

                // 快速过滤：this 前 128B 里含 FILEASSIST 才继续
                var raw = safeBytes(this._this_va, 128);
                if (raw && hasFA(toHex(raw))) { this._faInThis = true; }
                else this._faInThis = false;
            },
            onLeave: function(rv) {
                if (this._skip || !this._this_va) return;

                // 无论 FA-in-this 与否，都试着解 out std::string
                var out_ss = readStdString(this._out_va);
                var this_hex = null;
                var raw_this = safeBytes(this._this_va, 512);
                if (raw_this) this_hex = toHex(raw_this);

                // 是否含 FA（this 或 out.data）
                var fa = this._faInThis ||
                    (out_ss && out_ss.data_hex && hasFA(out_ss.data_hex));
                if (!fa) return;

                if (tag==='A') hitA++; else hitB++;
                var n = (tag==='A') ? hitA : hitB;

                var vt = readVtable(this._this_va);
                send({
                    t:'hit', tag:tag, n:n, tid:this.threadId,
                    ret_addr: '0x'+this.returnAddress.toUInt32().toString(16),
                    retval: rv.toUInt32(),
                    this_va: '0x'+this._this_va.toString(16),
                    out_va:  '0x'+this._out_va.toString(16),
                    out_ss: out_ss,
                    this_hex_512: this_hex,
                    vtable: vt
                });
            }
        });
        return true;
    } catch(e) { send({t:'fail', tag:tag, err:String(e)}); return false; }
}

var okA = attach(PTR_A, 'A');
var okB = attach(PTR_B, 'B');
send({t:'ready', okA:okA, okB:okB});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

hits = []
def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']; t = p.get('t')
    if t=='ready':
        print(f'[+] armed A={p["okA"]} B={p["okB"]}', flush=True); return
    if t=='fail':
        print(f'[!!] attach FAIL {p["tag"]}: {p["err"]}', flush=True); return
    if t!='hit': return

    hits.append(p)
    with (OUT_DIR/f'hook_serialize_v2_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    ss = p.get('out_ss') or {}
    ss_size = ss.get('size'); ss_mode = ss.get('mode'); ss_cap = ss.get('cap')
    vt = p.get('vtable') or {}
    print(f'\n★ [{p["tag"]}] HIT #{p["n"]}  this={p["this_va"]}  out={p["out_va"]}  '
          f'retval={p["retval"]}  vptr={vt.get("vptr")}', flush=True)
    if ss_size is not None:
        print(f'    out std::string  mode={ss_mode}  size={ss_size}  cap={ss_cap}  data_at={ss.get("data_addr")}', flush=True)
        hx = ss.get('data_hex', '')
        if hx:
            preview = bytes.fromhex(hx[:min(len(hx), 96*2)])
            ascii_pv = ''.join(chr(b) if 32<=b<127 else '.' for b in preview)
            print(f'    hex[:{len(preview)}]: {hx[:min(len(hx), 96*2)]}', flush=True)
            print(f'    ascii:  {ascii_pv}', flush=True)
        # 落盘
        if ss.get('data_hex'):
            fn = OUT_DIR / f'hook_v2_{ts}_{p["tag"]}_h{p["n"]:03d}_out.bin'
            fn.write_bytes(bytes.fromhex(ss['data_hex']))
    if p.get('this_hex_512'):
        fn = OUT_DIR / f'hook_v2_{ts}_{p["tag"]}_h{p["n"]:03d}_this.bin'
        fn.write_bytes(bytes.fromhex(p['this_hex_512']))
    print(f'    vtable[0..15]: {" ".join(vt.get("slots", [])[:16])}', flush=True)

def main():
    js = (JS_TPL.replace('__PTRA__', hex(PTR_A))
                .replace('__PTRB__', hex(PTR_B))
                .replace('__MAX__', str(MAX_HITS)))
    print('[*] PID …', flush=True); pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内 在企微【向 FTA 发 1 条唯一内容的文字（如 "PROTO_TEST_20260914"）】', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 共 {len(hits)} 次 FA HIT  产物：hook_v2_{ts}_*', flush=True)
    os._exit(0)

if __name__ == '__main__': main()
