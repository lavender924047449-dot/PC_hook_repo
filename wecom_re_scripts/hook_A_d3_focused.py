# hook_A_d3_focused.py — 集中打 A_d3 (0x0992c100)
# onEnter + onLeave 同时抓 args 与 this 的完整 8KB dump，
# 过滤条件：a0 或 ecx 指向的内存包含 FILEASSIST (46494c45415353495354)
# 目的：抓到 ConstructMessageProtobuf 的输出 proto 字节流

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90
TARGET_RVA = 0x0992c100
DUMP_SZ_ENTER = 4096
DUMP_SZ_LEAVE = 8192
MAX_HITS = 12

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var BASE = mod.base;
var TGT = BASE.add(__RVA__);
var PRESEND = BASE.add(0x919ffb2);
var MAX_HITS = __MAX_HITS__;
var DUMP_E = __DUMP_E__;
var DUMP_L = __DUMP_L__;

function safeBytes(a, sz) {
    try { var p = ptr(a); var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s='';
    for (var i=0;i<a.length;i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function hasFA(hex) { return hex.indexOf('46494c45415353495354') !== -1; }

// TLS: PreSend 窗口
var WIN = {tid_state: {}};
Interceptor.attach(PRESEND, {
    onEnter: function(args) { WIN.tid_state[this.threadId] = 1; },
    onLeave: function(rv) { delete WIN.tid_state[this.threadId]; }
});

var hit_cnt = 0;
Interceptor.attach(TGT, {
    onEnter: function(args) {
        if (!WIN.tid_state[this.threadId]) return;
        if (hit_cnt >= MAX_HITS) return;

        // 先看 ecx / a0 是否含 FILEASSIST
        var addrs = {};
        addrs.ecx = this.context.ecx.toUInt32();
        for (var i=0; i<6; i++) addrs['a'+i] = args[i].toUInt32();

        var ecx_raw = safeBytes(addrs.ecx, 256);
        var a0_raw  = safeBytes(addrs.a0, 256);
        var has_fa = (ecx_raw && hasFA(toHex(ecx_raw))) ||
                     (a0_raw && hasFA(toHex(a0_raw)));
        if (!has_fa) return;   // 只关心真的 message 发送

        hit_cnt++;
        this._n = hit_cnt;
        this._addrs = addrs;

        // enter 阶段：dump 大 buffer
        var dumps_e = {};
        Object.keys(addrs).forEach(function(k){
            var raw = safeBytes(addrs[k], DUMP_E);
            if (raw) dumps_e[k] = {addr:'0x'+addrs[k].toString(16), hex: toHex(raw)};
            else dumps_e[k] = {addr:'0x'+addrs[k].toString(16), null:true};
        });
        this._dumps_e = dumps_e;
    },
    onLeave: function(rv) {
        if (!this._addrs) return;
        var addrs = this._addrs;
        var rv_v = rv.toUInt32();
        // leave 阶段：重新 dump（很可能 a3 / ecx 里现在放着刚序列化好的 proto）
        var dumps_l = {};
        Object.keys(addrs).forEach(function(k){
            var raw = safeBytes(addrs[k], DUMP_L);
            if (raw) dumps_l[k] = {addr:'0x'+addrs[k].toString(16), hex: toHex(raw)};
            else dumps_l[k] = {addr:'0x'+addrs[k].toString(16), null:true};
        });
        // 若 retval 是 heap 指针，追一层
        var rv_dump = null;
        if (rv_v > 0x10000 && rv_v < 0x7F000000) {
            var raw = safeBytes(rv_v, DUMP_L);
            if (raw) rv_dump = {addr:'0x'+rv_v.toString(16), hex: toHex(raw)};
        }
        send({
            t:'hit', n:this._n, tid: this.threadId,
            addrs: addrs, retval: rv_v,
            e: this._dumps_e, l: dumps_l, rv_dump: rv_dump
        });
    }
});
send({t:'ready', addr: TGT.toString()});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')
    if t=='ready': print(f'[+] hooked A_d3 @ {p["addr"]}', flush=True); return
    if t!='hit': return

    n = p['n']
    print(f'\n★ HIT #{n}  ecx={p["addrs"].get("ecx"):#x}  a0={p["addrs"].get("a0"):#x}  '
          f'a3={p["addrs"].get("a3"):#x}  a5={p["addrs"].get("a5"):#x}  rv=0x{p["retval"]:x}', flush=True)
    # 落盘所有 dump
    for phase, key in [('enter','e'), ('leave','l')]:
        for k, d in p[key].items():
            if d.get('null') or not d.get('hex'): continue
            fn = OUT_DIR / f'hook_Ad3_{ts}_h{n}_{phase}_{k}.bin'
            fn.write_bytes(bytes.fromhex(d['hex']))
    if p.get('rv_dump'):
        fn = OUT_DIR / f'hook_Ad3_{ts}_h{n}_rv.bin'
        fn.write_bytes(bytes.fromhex(p['rv_dump']['hex']))
        print(f'  rv points to 0x{p["retval"]:x}, dumped {fn.name}', flush=True)
    # 快速 preview：从每 leave dump 里挑 ASCII 富含 proto 迹象的
    for k, d in p['l'].items():
        if d.get('null'): continue
        hx = d['hex']; raw = bytes.fromhex(hx)
        # 找可打印片段（>=8）
        run = b''; runs = []
        for b in raw:
            if 32 <= b < 127: run += bytes([b])
            else:
                if len(run) >= 8: runs.append(run.decode('ascii','replace'))
                run = b''
        if len(run) >= 8: runs.append(run.decode('ascii','replace'))
        top = runs[:6]
        if top:
            print(f'  leave {k} @ {d["addr"]}  ascii runs: {top}', flush=True)

def main():
    js = (JS_TPL.replace('__RVA__', str(TARGET_RVA))
                .replace('__MAX_HITS__', str(MAX_HITS))
                .replace('__DUMP_E__', str(DUMP_SZ_ENTER))
                .replace('__DUMP_L__', str(DUMP_SZ_LEAVE)))
    print('[*] PID …', flush=True); pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内 在企微【向 FTA 发 1 条文字 + 1 个小文件 + 1 张图/视频】', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 结束，产物：hook_Ad3_{ts}_*', flush=True)
    os._exit(0)

if __name__ == '__main__': main()
