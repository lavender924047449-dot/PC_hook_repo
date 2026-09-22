# hook_proto_vfunc2.py — v2：this dump 1KB + arg0 dump 4KB
# 目的：抓 CGI 请求输出缓冲的完整 proto envelope（不再限制 FA）
#
# 相比 v1 (hook_proto_vfunc.py) 改动：
#   - MAX_TOTAL 降到 30 (v1 是 400)
#   - this dump 从 512 → 1024
#   - arg0 dump 从 256 → 4096（★ 关键）
#   - 移除 FA 过滤（v1 里 FA 阳性 = 0，说明 FILEASSIST 不在 this 里）
#   - 每 hit 都落盘（无过滤）

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90

VFUNC_SERIALIZE = 0x09f042a0
VFUNC_BYTESIZE  = 0x09f03c40
MAX_TOTAL = 30

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(0x919ffb2);
var V_SER = ptr(__V_SER__);
var V_BYT = ptr(__V_BYT__);
var MAX_TOTAL = __MAX_TOTAL__;

function safeBytes(a, sz) {
    try { var p = (typeof a === 'number' || typeof a === 'string') ? ptr(a) : a;
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
function hasFA(hex) { return hex.indexOf('46494c45415353495354') !== -1; }
function readU32(ab, i) { var a=new Uint8Array(ab); return ((a[i]|(a[i+1]<<8)|(a[i+2]<<16)|(a[i+3]<<24))>>>0); }

var WIN = {tid_state:{}};
Interceptor.attach(PRESEND, {
    onEnter: function(){ WIN.tid_state[this.threadId] = 1; },
    onLeave: function(){ delete WIN.tid_state[this.threadId]; }
});

function makeHook(addr, tag, has_arg0) {
    var self = { cnt:0 };
    Interceptor.attach(addr, {
        onEnter: function(args) {
            if (!WIN.tid_state[this.threadId]) return;
            self.cnt++;
            if (self.cnt > MAX_TOTAL) return;

            var this_v;
            try { this_v = this.context.ecx.toUInt32(); } catch(e) { return; }
            var raw = safeBytes(this_v, 1024);
            if (!raw) return;
            var hex_this = toHex(raw);
            var vtable = readU32(raw, 0);
            var is_fa = hasFA(hex_this);

            var arg0_hex = null; var arg0_v = 0;
            if (has_arg0) {
                arg0_v = args[0].toUInt32();
                var raw2 = safeBytes(arg0_v, 4096);
                if (raw2) arg0_hex = toHex(raw2);
            }
            var arg0_is_fa = arg0_hex ? hasFA(arg0_hex) : false;

            send({
                t:'hit', tag:tag, n:self.cnt, tid:this.threadId,
                this_addr:'0x'+this_v.toString(16),
                vtable:'0x'+vtable.toString(16),
                arg0_addr:'0x'+arg0_v.toString(16),
                is_fa: is_fa, arg0_is_fa: arg0_is_fa,
                this_hex: hex_this,
                arg0_hex: arg0_hex,
                ret_addr:'0x'+this.returnAddress.toUInt32().toString(16),
            });
        }
    });
    return self;
}
makeHook(V_SER, 'SER', true);
makeHook(V_BYT, 'BYT', false);
send({t:'ready'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

hits = []
def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')
    if t == 'ready': print('[+] hooks armed (v2 with 4KB arg0 dump)', flush=True); return
    if t != 'hit': return

    hits.append(p)
    with (OUT_DIR/f'hook_vfunc2_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps({k:v for k,v in p.items() if k not in ('this_hex','arg0_hex')}, ensure_ascii=False)+'\n')

    fa = ''
    if p['is_fa']: fa += '★THIS-FA'
    if p['arg0_is_fa']: fa += ' ★ARG0-FA'
    print(f'[{p["tag"]}] #{p["n"]:02d}  this={p["this_addr"]}  vt={p["vtable"]}  arg0={p["arg0_addr"]}  {fa}', flush=True)
    # 落盘
    fn1 = OUT_DIR / f'hook_vfunc2_{ts}_h{p["n"]:03d}_{p["tag"]}_this.bin'
    fn1.write_bytes(bytes.fromhex(p['this_hex']))
    if p.get('arg0_hex'):
        fn2 = OUT_DIR / f'hook_vfunc2_{ts}_h{p["n"]:03d}_{p["tag"]}_arg0.bin'
        fn2.write_bytes(bytes.fromhex(p['arg0_hex']))

def main():
    js = (JS_TPL.replace('__V_SER__', str(VFUNC_SERIALIZE))
                .replace('__V_BYT__', str(VFUNC_BYTESIZE))
                .replace('__MAX_TOTAL__', str(MAX_TOTAL)))
    print('[*] PID …', flush=True); pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内 向 FTA 发【1 条明显的文字（比如 "VFUNC_TEST_XXX"）+ 1 个文件】', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    fa_this = sum(1 for h in hits if h['is_fa'])
    fa_a0 = sum(1 for h in hits if h['arg0_is_fa'])
    print(f'\n[+] hits={len(hits)}  FA-in-this={fa_this}  FA-in-arg0={fa_a0}', flush=True)
    os._exit(0)

if __name__ == '__main__': main()
