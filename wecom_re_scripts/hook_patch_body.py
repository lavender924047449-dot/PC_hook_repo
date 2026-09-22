# hook_patch_body.py — 在 SER (0x9f042a0) onEnter 里 in-place 覆写消息文本
# ★ 目标：验证 arg0/this 里的 body 字节是否为 encoder 输入
#
# 约定：
#   用户发 "PATCH_TEST_XXX"（14 chars → MSVC SSO 内联）
#   脚本改成      "PATCH_HACKED!!"（14 chars 同长度）
#   若 FTA 收到 "PATCH_HACKED!!" → S3+S4 一击达成
#   若 FTA 收到 "PATCH_TEST_XXX" → arg0/this 是快照，需要下游 CGI 层 patch
#
# 策略：
#   1. TLS 门控 PreSend 窗口
#   2. 每 SER hit：读 this 4KB + arg0 8KB
#   3. 扫 marker bytes（同长度 patch，不动 SSO size/cap dword）
#   4. 顺带 L1 chase：this/arg0 前 256 dword 若指向 heap，各读 256B 也扫一次
#      (捕获 heap-alloc >15 chars 场景，或 std::string 头 ptr 追随)
#   5. 每次 patch 前后 dump 32B 上下文（供离线验证）
#   6. 记录 patch 计数 + 落盘 ndjson

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90

VFUNC_SER = 0x09f042a0
MARKER_ORIG = 'PATCH_TEST_XXX'    # 14 chars
MARKER_NEW  = 'PATCH_HACKED!!'    # 14 chars
assert len(MARKER_ORIG) == len(MARKER_NEW), 'markers must be same length'

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(0x919ffb2);
var SER = ptr(__V_SER__);

var MARKER_ORIG_HEX = '__ORIG_HEX__';   // 14 bytes hex
var MARKER_NEW_HEX  = '__NEW_HEX__';    // 14 bytes hex
var MARKER_LEN = MARKER_ORIG_HEX.length / 2;

// hex -> Uint8Array
function hex2bytes(h) {
    var out = new Uint8Array(h.length/2);
    for (var i=0; i<h.length; i+=2) out[i/2] = parseInt(h.substr(i,2), 16);
    return out;
}
var MARKER_ORIG_BYTES = hex2bytes(MARKER_ORIG_HEX);
var MARKER_NEW_BYTES  = hex2bytes(MARKER_NEW_HEX);

function safeBytes(a, sz) {
    try { var p = (typeof a === 'number' || typeof a === 'string') ? ptr(a) : a;
        var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a=new Uint8Array(ab), s='';
    for (var i=0;i<a.length;i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function readU32(ab, i) { var a=new Uint8Array(ab); return ((a[i]|(a[i+1]<<8)|(a[i+2]<<16)|(a[i+3]<<24))>>>0); }

// 在 ArrayBuffer 里找 marker 的所有偏移
function findAll(ab, marker) {
    var a = new Uint8Array(ab), hits = [];
    var m0 = marker[0], mlen = marker.length;
    outer: for (var i=0; i<=a.length - mlen; i++) {
        if (a[i] !== m0) continue;
        for (var j=1; j<mlen; j++) if (a[i+j] !== marker[j]) continue outer;
        hits.push(i);
    }
    return hits;
}

// 就地 patch：在 base_va + offset 处写入 new bytes
function patchAt(base_va, offset) {
    try {
        Memory.protect(ptr(base_va + offset), MARKER_LEN, 'rwx');
        ptr(base_va + offset).writeByteArray(Array.from(MARKER_NEW_BYTES));
        return true;
    } catch(e) { return false; }
}

var WIN = {tid_state:{}};
Interceptor.attach(PRESEND, {
    onEnter: function(){ WIN.tid_state[this.threadId] = 1; },
    onLeave: function(){ delete WIN.tid_state[this.threadId]; }
});

var hit_cnt = 0, patch_total = 0;
Interceptor.attach(SER, {
    onEnter: function(args) {
        if (!WIN.tid_state[this.threadId]) return;
        hit_cnt++;
        if (hit_cnt > 60) return;

        var patches = [];

        // (1) 扫 this 4KB
        var this_v; try { this_v = this.context.ecx.toUInt32(); } catch(e) { return; }
        var this_raw = safeBytes(this_v, 4096);
        if (this_raw) {
            var hs = findAll(this_raw, MARKER_ORIG_BYTES);
            for (var k=0; k<hs.length; k++) {
                var ok = patchAt(this_v, hs[k]);
                patches.push({loc:'this', addr:'0x'+(this_v+hs[k]).toString(16), off:hs[k], ok:ok});
            }
        }

        // (2) 扫 arg0 8KB
        var a0v = args[0].toUInt32();
        var a0_raw = safeBytes(a0v, 8192);
        if (a0_raw) {
            var hs = findAll(a0_raw, MARKER_ORIG_BYTES);
            for (var k=0; k<hs.length; k++) {
                var ok = patchAt(a0v, hs[k]);
                patches.push({loc:'arg0', addr:'0x'+(a0v+hs[k]).toString(16), off:hs[k], ok:ok});
            }
        }

        // (3) L1 chase：this 前 256 dword 若指向 heap，扫 256B
        if (this_raw) {
            var chased = 0;
            for (var i=0; i+3<Math.min(this_raw.byteLength, 1024) && chased<32; i+=4) {
                var p = readU32(this_raw, i);
                if (p < 0x10000 || p > 0x7F000000) continue;
                var sub = safeBytes(p, 256);
                if (!sub) continue;
                chased++;
                var hs = findAll(sub, MARKER_ORIG_BYTES);
                for (var k=0; k<hs.length; k++) {
                    var ok = patchAt(p, hs[k]);
                    patches.push({loc:'this_L1@0x'+i.toString(16), addr:'0x'+(p+hs[k]).toString(16), off:hs[k], ok:ok});
                }
            }
        }
        // (4) L1 chase：arg0 前 256 dword 同样
        if (a0_raw) {
            var chased = 0;
            for (var i=0; i+3<Math.min(a0_raw.byteLength, 1024) && chased<32; i+=4) {
                var p = readU32(a0_raw, i);
                if (p < 0x10000 || p > 0x7F000000) continue;
                var sub = safeBytes(p, 256);
                if (!sub) continue;
                chased++;
                var hs = findAll(sub, MARKER_ORIG_BYTES);
                for (var k=0; k<hs.length; k++) {
                    var ok = patchAt(p, hs[k]);
                    patches.push({loc:'arg0_L1@0x'+i.toString(16), addr:'0x'+(p+hs[k]).toString(16), off:hs[k], ok:ok});
                }
            }
        }

        if (patches.length > 0) {
            patch_total += patches.length;
            var vtable = this_raw ? readU32(this_raw, 0) : 0;
            send({
                t:'patch', hit_n: hit_cnt, tid: this.threadId,
                this_addr:'0x'+this_v.toString(16),
                arg0_addr:'0x'+a0v.toString(16),
                vtable:'0x'+vtable.toString(16),
                patches: patches,
                total_so_far: patch_total,
            });
        }
    }
});
send({t:'ready', orig:'__ORIG__', new_:'__NEW__'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

patches_log = []
def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')
    if t == 'ready':
        print(f'[+] hook armed. orig={p["orig"]!r}  new={p["new_"]!r}', flush=True); return
    if t != 'patch': return
    patches_log.append(p)
    with (OUT_DIR/f'patch_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')
    print(f'\n★ PATCH hit #{p["hit_n"]}  this={p["this_addr"]}  vt={p["vtable"]}  arg0={p["arg0_addr"]}', flush=True)
    for pt in p['patches']:
        ok = '✓' if pt['ok'] else '✗'
        print(f'  {ok} [{pt["loc"]:<18}] {pt["addr"]}  (off=+0x{pt["off"]:x})', flush=True)


def main():
    orig_hex = MARKER_ORIG.encode().hex()
    new_hex = MARKER_NEW.encode().hex()
    js = (JS_TPL.replace('__V_SER__', str(VFUNC_SER))
                .replace('__ORIG_HEX__', orig_hex)
                .replace('__NEW_HEX__', new_hex)
                .replace('__ORIG__', MARKER_ORIG)
                .replace('__NEW__', MARKER_NEW))
    print(f'[*] marker: {MARKER_ORIG!r} -> {MARKER_NEW!r}  (len={len(MARKER_ORIG)})', flush=True)
    print('[*] PID …', flush=True); pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}', flush=True)
    print(f'★★★ 请在 {CAPTURE_SEC}s 内 向 FTA 发送 精确文字：', flush=True)
    print(f'      {MARKER_ORIG}', flush=True)
    print(f'    发完后打开 FTA 看收到的是原文还是 "{MARKER_NEW}"', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    n_hits = len(patches_log)
    n_patches = sum(len(p['patches']) for p in patches_log)
    print(f'\n[+] {n_hits} PATCH-HIT，共 {n_patches} 处覆写', flush=True)
    print(f'[+] 结果验证：FTA 现在看到 {MARKER_NEW!r} 还是 {MARKER_ORIG!r}?', flush=True)
    os._exit(0)

if __name__ == '__main__': main()
