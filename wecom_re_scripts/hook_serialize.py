# hook_serialize.py — 直接 hook 76 条 Extra* 共享的 proto 虚函数指针
#
# 目标（§47.12.7 交接的 P0-A）：
#   ptr_A = 0x09f042a0   疑 SerializeWithCachedSizes(this, CodedOutputStream*)
#   ptr_B = 0x09f03c40   疑 ByteSizeLong(this) const
#   两者都通过 vtable indirect call 触发，静态 BFS 追不到，只能直接 hook 绝对地址
#
# 策略：
#   1. TLS 门控在 PreSend 窗口内触发（避免 UI 层轰炸），窗口外的调用 drop
#   2. onEnter dump `ecx` = this = proto Message 前 2KB → 明文字段
#      顺便 dump args[0..3] 各 512B（可能是 CodedOutputStream* 或输出 buffer）
#   3. 每 hook 最多 200 次（一次 send 涉及嵌套字段可能百级 SerializeWithCachedSizes 调用）
#   4. 过滤：ecx 或某 arg 指向的内存里出现 "FILEASSIST" (46494c45415353495354) 才落盘
#      —— 只关心真的 message 发送
#
# 产物：
#   hook_serialize_<ts>.ndjson              全事件流
#   hook_serialize_<ts>_h<N>_{A,B}_{ecx,a0..a3}.bin   命中的原始 dump
#   hook_serialize_<ts>_summary.txt         按 fn 计次 + 明文预览

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90

# 从 §47.12.2/3 拆解 pool 得的两个共享 fn ptr（76/76 entry 都出现）
# 这些是运行时 abs VA（从 pool dump 里读到的 dword 值）
PTR_A = 0x09f042a0  # SerializeWithCachedSizes 强候选
PTR_B = 0x09f03c40  # ByteSizeLong 强候选
PRESEND_RVA = 0x919ffb2
MAX_HITS_PER_FN = 200
DUMP_ECX = 2048
DUMP_ARG = 512

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var BASE = mod.base;
var PRESEND = BASE.add(0x919ffb2);
var PTR_A = ptr('__PTRA__');
var PTR_B = ptr('__PTRB__');
var MAX = __MAX__;
var DUMP_E = __DUMPE__;
var DUMP_A = __DUMPA__;

function safeBytes(a, sz) {
    try { var p = (typeof a === 'object') ? a : ptr(a);
        var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s='';
    for (var i=0; i<a.length; i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function hasFA(hex) { return hex.indexOf('46494c45415353495354') !== -1; }
function asciiStrs(ab, minLen) {
    minLen = minLen || 6;
    var a = new Uint8Array(ab), out=[], run='', st=0;
    for (var i=0; i<a.length; i++) {
        if (a[i]>=0x20 && a[i]<=0x7E) { if (!run.length) st=i; run += String.fromCharCode(a[i]); }
        else { if (run.length>=minLen) out.push({o:st,s:run}); run=''; }
    }
    if (run.length>=minLen) out.push({o:st,s:run});
    return out;
}
// 前几个 pb tag（用于快速判断是不是 proto 字节流）
function pbTags(ab) {
    var a = new Uint8Array(ab), out=[], i=0;
    for (var k=0; k<10 && i<a.length; k++) {
        var v=0, sh=0, ok=false, st=i;
        while (i<a.length && i-st<5) { var b=a[i++]; v |= (b&0x7f)<<sh; sh+=7; if (!(b&0x80)) {ok=true;break;} }
        if (!ok) break;
        var wt=v&7, f=v>>>3;
        if (f===0 || f>250 || wt===3 || wt===4 || wt>5) break;
        out.push('f'+f+'w'+wt);
        if (wt===0) { while (i<a.length && (a[i]&0x80)) i++; i++; }
        else if (wt===1) i+=8;
        else if (wt===5) i+=4;
        else if (wt===2) {
            var L=0,sh2=0,st2=i;
            while (i<a.length && i-st2<5) { var bb=a[i++]; L|=(bb&0x7f)<<sh2; sh2+=7; if (!(bb&0x80)) break; }
            if (L > ab.byteLength) L = 0;
            i += L;
        }
    }
    return out;
}

var WIN = {tid: {}};
var hitA = 0, hitB = 0;
var TOTAL_A = 0, TOTAL_B = 0;   // 含窗口外的原始触发计数（估算 fn 使用频度）

Interceptor.attach(PRESEND, {
    onEnter: function(a) { WIN.tid[this.threadId] = 1; },
    onLeave: function(r) { delete WIN.tid[this.threadId]; }
});

function attachSerialize(addr, tag, incFn) {
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                incFn();
                if (!WIN.tid[this.threadId]) return;
                if ((tag==='A' && hitA >= MAX) || (tag==='B' && hitB >= MAX)) return;

                var ecxv = this.context.ecx.toUInt32();
                var ecx_raw = safeBytes(ecxv, DUMP_E);
                var ecx_hex = ecx_raw ? toHex(ecx_raw) : null;

                var arg_dumps = {};
                for (var i=0; i<4; i++) {
                    var v = args[i].toUInt32();
                    var raw = safeBytes(v, DUMP_A);
                    if (raw) arg_dumps['a'+i] = {v:'0x'+v.toString(16), hex: toHex(raw)};
                    else arg_dumps['a'+i] = {v:'0x'+v.toString(16), null:true};
                }

                // 过滤：ecx / a0..a3 里含 FILEASSIST 才落
                var has = ecx_hex && hasFA(ecx_hex);
                if (!has) {
                    for (var k in arg_dumps) if (arg_dumps[k].hex && hasFA(arg_dumps[k].hex)) { has = true; break; }
                }
                if (!has) return;

                if (tag==='A') hitA++; else hitB++;
                var n = (tag==='A') ? hitA : hitB;

                var ecx_meta = ecx_raw ? {
                    hex: ecx_hex,
                    tags: pbTags(ecx_raw),
                    strs: asciiStrs(ecx_raw, 6).slice(0, 8),
                    fa: hasFA(ecx_hex)
                } : null;

                send({t:'hit', tag:tag, n:n, tid:this.threadId,
                      ret_addr: '0x'+this.returnAddress.toUInt32().toString(16),
                      ecx: {v:'0x'+ecxv.toString(16), d: ecx_meta},
                      args: arg_dumps});
            }
        });
        return true;
    } catch(e) {
        send({t:'attach_fail', tag:tag, err: String(e)});
        return false;
    }
}

var okA = attachSerialize(PTR_A, 'A', function(){TOTAL_A++;});
var okB = attachSerialize(PTR_B, 'B', function(){TOTAL_B++;});
send({t:'ready', okA:okA, okB:okB, base:BASE.toString(),
      ptrA: PTR_A.toString(), ptrB: PTR_B.toString()});

// 定期汇报总计数（含窗口外）
setInterval(function(){
    send({t:'stat', totA: TOTAL_A, totB: TOTAL_B, hitA: hitA, hitB: hitB});
}, 15000);
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
        print(f'[+] armed A={p["okA"]} B={p["okB"]}  base={p["base"]}', flush=True)
        print(f'    PTR_A={p["ptrA"]}  PTR_B={p["ptrB"]}', flush=True); return
    if t=='attach_fail':
        print(f'[!!] attach FAIL {p["tag"]}: {p["err"]}', flush=True); return
    if t=='stat':
        print(f'  [stat] total_A={p["totA"]}  total_B={p["totB"]}  FA_hit_A={p["hitA"]}  FA_hit_B={p["hitB"]}', flush=True); return
    if t!='hit': return

    hits.append(p)
    with (OUT_DIR/f'hook_serialize_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    ec = p['ecx']; d = ec['d'] or {}
    tags_str = ','.join(d.get('tags', [])[:6])
    strs_str = ' | '.join(s['s'][:24] for s in d.get('strs', [])[:3])
    fa = '★FA' if d.get('fa') else ''
    print(f'\n★ [{p["tag"]}] HIT #{p["n"]}  ret={p["ret_addr"]}  ecx={ec["v"]}  {fa}  '
          f'pb_tags=[{tags_str}]', flush=True)
    if strs_str: print(f'    ecx strs: {strs_str}', flush=True)

    # 落 bin
    if d.get('hex'):
        fn = OUT_DIR / f'hook_serialize_{ts}_{p["tag"]}_h{p["n"]:03d}_ecx.bin'
        fn.write_bytes(bytes.fromhex(d['hex']))
    for k, ad in p['args'].items():
        if ad.get('null') or not ad.get('hex'): continue
        fn = OUT_DIR / f'hook_serialize_{ts}_{p["tag"]}_h{p["n"]:03d}_{k}.bin'
        fn.write_bytes(bytes.fromhex(ad['hex']))

def main():
    js = (JS_TPL.replace('__PTRA__', hex(PTR_A))
                .replace('__PTRB__', hex(PTR_B))
                .replace('__MAX__', str(MAX_HITS_PER_FN))
                .replace('__DUMPE__', str(DUMP_ECX))
                .replace('__DUMPA__', str(DUMP_ARG)))
    print('[*] PID …', flush=True); pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内 在企微【向 FTA 依次发：1 条文字 + 1 张图 + 1 个文件】\n'
          f'    尽量让消息内容有 unique 标识（便于 diff proto 字段）', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass

    # summary
    tally = {}
    for p in hits:
        k = (p['tag'], p['ret_addr'])
        tally[k] = tally.get(k, 0) + 1
    print(f'\n[+] 共 {len(hits)} 次 FA-命中 (窗口内)  产物：hook_serialize_{ts}_*', flush=True)
    print(f'    按 (tag, ret_addr) 分布 (top 15):')
    for (tag, ret), n in sorted(tally.items(), key=lambda kv: -kv[1])[:15]:
        print(f'      [{tag}] ret={ret}  x{n}')
    os._exit(0)

if __name__ == '__main__': main()
