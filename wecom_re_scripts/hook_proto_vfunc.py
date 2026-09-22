# hook_proto_vfunc.py — hook 76 条 Extra* proto entry 共享的两个虚函数
# ★ 目标：dump proto Message (this) 明文字段
#
# 依据 §47.12.3 parse 结果：
#   0x09f042a0 (76× 共享) —— 疑 SerializeWithCachedSizes(CodedOutputStream*)
#   0x09f03c40 (76× 共享) —— 疑 ByteSizeLong() const
#
# 两个都是 __thiscall 虚函数：
#   ecx = this = proto Message 本尊（成员变量顺序 = proto 字段顺序）
#   ByteSizeLong: 无 args，返回 size
#   SerializeWithCachedSizes: args[0] = CodedOutputStream*, 无返回
#
# 策略：
#   1. 用 abs 地址 hook（不加 mod.base，因为 §47.12.2 里这些 ptr 是 pool 中的 runtime 值）
#   2. TLS 门控 PreSend 窗口，避免 UI 层调用轰炸
#   3. 每 hit dump ecx 前 512B + vtable ptr this[0] + args[0]（若适用）256B
#   4. 过滤：只保留 ecx dump 含 FILEASSIST sentinel（真发消息）的
#   5. 顺带记录 this[0] (vtable) → 反查 76 条 entry 表识别 proto 类型
#
# 产物：hook_vfunc_<ts>.ndjson + hook_vfunc_<ts>_h{N}_{fn}_{k}.bin

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90

# 两个虚函数（runtime abs）
VFUNC_SERIALIZE = 0x09f042a0   # SerializeWithCachedSizes 疑似
VFUNC_BYTESIZE  = 0x09f03c40   # ByteSizeLong 疑似

# 每 fn 最多保存的 FA-阳性 hit 数（防爆盘）
MAX_FA_HITS = 20
# 每 fn 最多 hit 总数（含非 FA 的，也用于统计）
MAX_TOTAL_HITS = 400

# 加载 76 条 entry 表，做 vtable → proto 类型反查
POOL_JSON = None
for p in sorted(OUT_DIR.glob('parse_typeurl_pool_*.json'),
                key=lambda p: p.stat().st_mtime, reverse=True):
    POOL_JSON = p; break
pool_meta = {}
if POOL_JSON:
    j = json.loads(POOL_JSON.read_text(encoding='utf-8'))
    # 每条 entry 的所有 dword 都可能是 vtable，最强的是 fn ptr（.text 范围内）
    # 我们额外做一个：每 entry 的 fn ptr 集合，若 this[0] (vtable) 命中，就说它是这个 proto 类型
    # 简化：把每 entry 的所有 fn ptr 都当作可能的 vtable 候选
    ep = {}
    for e in j['entries']:
        for _, fp in [(0,d) for d in e['dwords'] if 0x400000 <= d < 0x0c000000]:
            ep.setdefault(fp, []).append((e['idx'], e['type_url']))
    pool_meta['fnptr_to_type'] = ep
    print(f'[*] loaded pool: {POOL_JSON.name}  {len(j["entries"])} entries, {len(ep)} fn ptrs')
else:
    print('[!] no pool json, vtable resolution disabled')

FNPTR_TO_TYPE = pool_meta.get('fnptr_to_type', {})

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(0x919ffb2);
var V_SER = ptr(__V_SER__);   // 绝对地址
var V_BYT = ptr(__V_BYT__);
var MAX_FA = __MAX_FA__;
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
function asciiStrs(ab, minLen) {
    minLen = minLen || 4;
    var a=new Uint8Array(ab), out=[], run='', st=0;
    for (var i=0;i<a.length;i++) {
        if (a[i]>=0x20 && a[i]<=0x7E) { if(!run.length) st=i; run += String.fromCharCode(a[i]); }
        else { if(run.length>=minLen) out.push({o:st,s:run}); run=''; }
    }
    if(run.length>=minLen) out.push({o:st,s:run});
    return out;
}

// TLS PreSend 窗口
var WIN = {tid_state:{}};
Interceptor.attach(PRESEND, {
    onEnter: function(){ WIN.tid_state[this.threadId] = 1; },
    onLeave: function(){ delete WIN.tid_state[this.threadId]; }
});

function makeHook(addr, tag, has_arg0) {
    var cnt = 0, fa_cnt = 0;
    var self = { cnt:0, fa_cnt:0, tag:tag };
    Interceptor.attach(addr, {
        onEnter: function(args) {
            if (!WIN.tid_state[this.threadId]) return;
            self.cnt++;
            if (self.cnt > MAX_TOTAL) return;

            var this_v;
            try { this_v = this.context.ecx.toUInt32(); } catch(e) { return; }
            var raw = safeBytes(this_v, 512);
            if (!raw) return;
            var hex = toHex(raw);
            var is_fa = hasFA(hex);
            if (is_fa) self.fa_cnt++;
            if (!is_fa && self.fa_cnt >= MAX_FA) return;  // 已收够 FA 后忽略非 FA
            if (self.fa_cnt > MAX_FA && is_fa) return;

            // vtable = this[0]
            var vtable = readU32(raw, 0);
            var strs = asciiStrs(raw, 4).slice(0, 12).map(function(x){return {o:x.o, s:x.s.slice(0,48)};});

            var arg0_dump = null;
            if (has_arg0) {
                var a0v = args[0].toUInt32();
                var raw2 = safeBytes(a0v, 256);
                if (raw2) arg0_dump = {addr:'0x'+a0v.toString(16), hex: toHex(raw2)};
            }

            send({
                t:'hit', tag: tag, n: self.cnt, fa_n: self.fa_cnt,
                tid: this.threadId,
                this_addr: '0x'+this_v.toString(16),
                is_fa: is_fa,
                vtable: '0x'+vtable.toString(16),
                this_hex: hex,
                strs: strs,
                arg0: arg0_dump,
                ret_addr: '0x'+this.returnAddress.toUInt32().toString(16),
            });
        }
    });
    return self;
}

// 验证地址可 hook
var ser_ok = false, byt_ok = false;
try {
    var probe = safeBytes(V_SER, 4);
    ser_ok = probe !== null;
} catch(e){}
try {
    var probe = safeBytes(V_BYT, 4);
    byt_ok = probe !== null;
} catch(e){}
send({t:'probe', v_ser: V_SER.toString(), ser_ok: ser_ok,
      v_byt: V_BYT.toString(), byt_ok: byt_ok});

if (ser_ok) makeHook(V_SER, 'SER', true);
if (byt_ok) makeHook(V_BYT, 'BYT', false);

send({t:'ready'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

hits = {'SER': [], 'BYT': []}
def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')
    if t == 'probe':
        print(f'[*] probe: SER {p["v_ser"]} ok={p["ser_ok"]}  BYT {p["v_byt"]} ok={p["byt_ok"]}', flush=True)
        return
    if t == 'ready':
        print(f'[+] hooks armed', flush=True); return
    if t != 'hit': return

    hits[p['tag']].append(p)
    with (OUT_DIR/f'hook_vfunc_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    # 落盘 this dump
    fa_tag = 'FA' if p['is_fa'] else 'other'
    fn = OUT_DIR / f'hook_vfunc_{ts}_h{p["n"]:04d}_{p["tag"]}_{fa_tag}_this.bin'
    fn.write_bytes(bytes.fromhex(p['this_hex']))
    if p.get('arg0'):
        fn2 = OUT_DIR / f'hook_vfunc_{ts}_h{p["n"]:04d}_{p["tag"]}_{fa_tag}_arg0.bin'
        fn2.write_bytes(bytes.fromhex(p['arg0']['hex']))

    if p['is_fa']:
        # vtable 反查 proto 类型
        vt = int(p['vtable'], 16)
        type_info = FNPTR_TO_TYPE.get(vt, [])
        type_str = ','.join(f'#{t[0]}:{t[1]}' for t in type_info[:2]) if type_info else '(unknown vtable)'
        strs_preview = ' | '.join(s['s'][:32] for s in p['strs'][:4])
        print(f'★FA [{p["tag"]}] #{p["n"]:04d}  this={p["this_addr"]}  vt={p["vtable"]}  '
              f'proto_type={type_str}', flush=True)
        print(f'      strs: {strs_preview}', flush=True)


def main():
    js = (JS_TPL
          .replace('__V_SER__', str(VFUNC_SERIALIZE))
          .replace('__V_BYT__', str(VFUNC_BYTESIZE))
          .replace('__MAX_FA__', str(MAX_FA_HITS))
          .replace('__MAX_TOTAL__', str(MAX_TOTAL_HITS)))
    print('[*] PID …', flush=True); pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内 在企微【向 FTA 发 1 条文字 + 1 个小文件 + 1 张图】', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] SER hits={len(hits["SER"])}  BYT hits={len(hits["BYT"])}', flush=True)
    fa_s = sum(1 for h in hits['SER'] if h['is_fa'])
    fa_b = sum(1 for h in hits['BYT'] if h['is_fa'])
    print(f'[+] FA-阳性: SER={fa_s}  BYT={fa_b}', flush=True)
    print(f'[+] 产物：hook_vfunc_{ts}_*', flush=True)
    os._exit(0)


if __name__ == '__main__': main()
