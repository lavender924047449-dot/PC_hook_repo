# hook_callchain.py — 一次跑机内追出 PreSendNewMessage → ConstructMessageProtobuf 全链
#
# 原理：把 §find_callchain.py 静态发现的 688 个 fn（depth 1..5）全部 attach，
# 每个 hook 只做一件事：如果当前线程正处于 PreSend 执行窗口（TLS flag），
#   就把 {seq, va, esp_top_4args} 塞进 buffer。
# PreSend onLeave 时打包吐给 Python，落盘 ndjson。
#
# 每个候选还做「args 轻扫描」：4 个可能的入参 dword，若指向可读内存，
#   取前 96 bytes hex + 存在的 ASCII 串（找 "FILEASSIST" 之类 conv_id 印记）。
#
# 产物：
#   callchain_trace_<ts>.ndjson         - 每个 PreSend HIT 的完整 call sequence
#   callchain_trace_<ts>_hit<N>.txt     - 单次 HIT 的可读时序表
#
# 使用：让用户在 60s 内向 FTA 发 2 条不同消息（文字 + 文件），
#   之后离线分析：哪个 fn 的 arg 里含 protobuf-like buffer / 唯一次 call / 深层 leaf。

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CHAIN_JSON = None    # 自动挑最新
CAPTURE_SEC = 90
PRESEND_RVA = 0x919ffb2
MAX_HITS = 6
IMAGE_BASE = 0x00400000

ts = datetime.now().strftime('%Y%m%d_%H%M%S')


def pick_chain_json():
    cands = sorted(OUT_DIR.glob('callchain_*.json'),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    # 排除 trace 输出
    cands = [c for c in cands if 'trace' not in c.name and '_flat' not in c.name]
    if not cands:
        raise SystemExit('no callchain_*.json found; run find_callchain.py first')
    return cands[0]


def load_targets():
    j = json.loads(pick_chain_json().read_text(encoding='utf-8'))
    print(f'[*] using chain: {pick_chain_json().name} ({j["meta"]["total_fns"]} fns)', flush=True)
    # depth ≥ 1（PreSend 本身 depth=0，另外 hook）
    targets = []
    for fn in j['functions']:
        if fn['depth'] == 0:
            continue
        targets.append({'rva': fn['rva'], 'depth': fn['depth']})
    # 去重（同一 rva 可能被多父调用列表指向，但 fn 表里每 fn 只有一条）
    seen = set(); uniq = []
    for t in targets:
        if t['rva'] in seen: continue
        seen.add(t['rva']); uniq.append(t)
    print(f'[*] hooking {len(uniq)} candidate fns (depth 1..5)', flush=True)
    return uniq


TARGETS = load_targets()

# ------------------- JS -------------------
JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var BASE = mod.base;
var PRESEND = BASE.add(0x919ffb2);
var TARGETS = __TARGETS__;      // [{rva, depth}, ...]
var MAX_HITS = __MAX_HITS__;
var IMAGE_BASE = 0x400000;

var TLS_KEY_ACTIVE = 'presend_active';
var TLS_KEY_SEQ    = 'presend_seq';
var TLS_KEY_LOG    = 'presend_log';
var hit_cnt = 0;

// 全局 depth 表 (rva -> depth) 供追加信息
var DEPTH = {};
for (var i=0; i<TARGETS.length; i++) DEPTH[TARGETS[i].rva] = TARGETS[i].depth;

function safeBytes(a, sz) {
    try { var p = ptr(a); var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s = '';
    for (var i=0; i<a.length; i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function asciiStrs(ab, minLen) {
    minLen = minLen || 4;
    var a = new Uint8Array(ab), out = [], run = '', st = 0;
    for (var i=0; i<a.length; i++) {
        if (a[i] >= 0x20 && a[i] <= 0x7E) {
            if (!run.length) st = i; run += String.fromCharCode(a[i]);
        } else {
            if (run.length >= minLen) out.push({o:st, s:run});
            run = '';
        }
    }
    if (run.length >= minLen) out.push({o:st, s:run});
    return out;
}
// protobuf-likeness：前 32 字节里有多少个合法 wire tag (低 3 位 <= 5, 高 5 位 field# >0 且 <= 30)
function pbScore(ab) {
    var a = new Uint8Array(ab), off = 0, tags = 0, bytes_used = 0, max_field = 0;
    while (off < a.length && off < 64 && tags < 8) {
        // 读 varint
        var v = 0, shift = 0, i = off, ok = false;
        while (i < a.length && i - off < 5) {
            var b = a[i++]; v |= (b & 0x7f) << shift; shift += 7;
            if ((b & 0x80) === 0) { ok = true; break; }
        }
        if (!ok) break;
        var wt = v & 7, field = v >>> 3;
        if (field === 0 || field > 200) break;
        if (wt > 5 || wt === 3 || wt === 4) break;  // reserved/deprecated
        tags++; if (field > max_field) max_field = field;
        // 跳过对应 payload
        if (wt === 0) {  // varint
            while (i < a.length && (a[i] & 0x80)) i++;
            i++;
        } else if (wt === 1) i += 8;
        else if (wt === 5) i += 4;
        else if (wt === 2) {
            // length-delimited: 读长度 varint
            var L = 0, sh = 0, k = i;
            while (k < a.length && k - i < 5) {
                var bb = a[k++]; L |= (bb & 0x7f) << sh; sh += 7;
                if ((bb & 0x80) === 0) break;
            }
            i = k + L;
        }
        off = i;
        bytes_used = i;
    }
    return {tags: tags, bytes: bytes_used, max_field: max_field};
}

function sampleArg(av) {
    var raw = safeBytes(av, 128);
    if (!raw) return null;
    var s = asciiStrs(raw, 4).slice(0, 4).map(function(x){return {o:x.o, s:x.s.slice(0,32)};});
    var pb = pbScore(raw);
    return {
        hex: toHex(raw).slice(0, 96*2),
        strs: s,
        pb: pb
    };
}

var WIN = {tid_state: {}};

// —— hook PreSend ——
Interceptor.attach(PRESEND, {
    onEnter: function(args) {
        if (hit_cnt >= MAX_HITS) return;
        var tid = this.threadId;
        var store = Process.getCurrentThreadId ? {} : {};   // no per-thread native; use context storage
        this._tid = tid;
        this._active = true;
        // 用 Interceptor 提供的 this-object 作 storage
        this._log = [];
        this._seq = 0;
        this._msg_hex = null;
        this._conv_hex = null;
        // 记 MessageObject 的 conv_id (args[1]+0x13c) 作 sentinel
        try {
            var mo = args[1].toUInt32();
            var conv_hex = null;
            if (mo > 0x10000 && mo < 0x7f000000) {
                var raw = ptr(mo + 0x13c).readByteArray(16);
                conv_hex = toHex(raw);
            }
            this._conv_hex = conv_hex;
        } catch(e){}
        // 把 stack 引用挂到线程对象上，供 target hook 读
        WIN.tid_state[tid] = this;
    },
    onLeave: function(retval) {
        if (!this._active) return;
        var tid = this._tid;
        hit_cnt++;
        var pkg = {
            t: 'presend_done',
            n: hit_cnt,
            tid: tid,
            retval: retval.toUInt32(),
            conv_hex: this._conv_hex,
            n_events: this._log.length,
            events: this._log,
        };
        delete WIN.tid_state[tid];
        send(pkg);
    }
});

// —— hook 所有候选 ——
var installed = 0;
for (var ti=0; ti<TARGETS.length; ti++) (function(rva, depth){
    var addr = BASE.add(rva);
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var tid = this.threadId;
                var pst = WIN.tid_state[tid];
                if (!pst) return;   // 不在 PreSend 窗口
                var seq = pst._seq++;
                if (seq > 3000) return;   // 上限保护
                // sample 4 args + ecx（thiscall）
                var samples = [];
                for (var i=0; i<4; i++) {
                    var v = args[i].toUInt32();
                    samples.push({v: '0x'+v.toString(16), d: sampleArg(v)});
                }
                var ecx_s = null;
                try {
                    var ecxv = this.context.ecx.toUInt32();
                    ecx_s = {v: '0x'+ecxv.toString(16), d: sampleArg(ecxv)};
                } catch(e){}
                pst._log.push({
                    seq: seq, rva: rva, depth: depth,
                    ret_addr: '0x'+this.returnAddress.toUInt32().toString(16),
                    args: samples,
                    ecx: ecx_s
                });
            }
        });
        installed++;
    } catch(e) { /* 有些 addr 不可 hook（对齐/thunk） */ }
})(TARGETS[ti].rva, TARGETS[ti].depth);

send({t:'ready', installed: installed, of: TARGETS.length, base: BASE.toString()});
"""

hits = []
def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']; t = p.get('t')
    if t == 'ready':
        print(f'[+] hooks installed: {p["installed"]}/{p["of"]}  base={p["base"]}', flush=True)
        return
    if t != 'presend_done': return

    hits.append(p)
    with (OUT_DIR/f'callchain_trace_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    print(f'\n{"="*72}\n★ PreSend HIT #{p["n"]}  conv_hex[:16]={p["conv_hex"]}  events={p["n_events"]}', flush=True)

    # 写单次 HIT 的时序表
    txt_path = OUT_DIR / f'callchain_trace_{ts}_hit{p["n"]}.txt'
    lines = [
        f'# PreSend HIT #{p["n"]} tid={p["tid"]} retval=0x{p["retval"]:x}',
        f'# conv_hex(16B @ +0x13c) = {p["conv_hex"]}',
        f'# events = {p["n_events"]}',
        '# seq  depth  rva        pb(tags/bytes/max_field)  arg_pointers  ascii_hint',
    ]
    for ev in p['events']:
        # 挑 protobuf-最像 的 arg（tags 最多）
        best = None
        for i, a in enumerate(ev['args']):
            d = a['d']
            if not d: continue
            pb = d['pb']; sc = pb['tags'] * 100 + pb['bytes']
            if not best or sc > best[1]:
                best = ([i, a, d], sc)
        pb_str = ''
        arg_str = ' '.join(a['v'] for a in ev['args'])
        hint = ''
        if best:
            _, arg, d = best[0]
            pb = d['pb']
            pb_str = f'{pb["tags"]}/{pb["bytes"]}/{pb["max_field"]}'
            if d['strs']:
                hint = ','.join(s['s'][:20] for s in d['strs'][:2])
        lines.append(f'{ev["seq"]:>4}  {ev["depth"]}     0x{ev["rva"]:08x}  {pb_str:<20}  {arg_str}  {hint}')
    txt_path.write_text('\n'.join(lines), encoding='utf-8')
    print(f'  → wrote {txt_path.name}', flush=True)


def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')


def main():
    js = (JS_TPL
          .replace('__TARGETS__', json.dumps(TARGETS))
          .replace('__MAX_HITS__', str(MAX_HITS)))
    print('[*] PID …', flush=True)
    pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()

    import time
    print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内 在企微【向 FTA 发 1 条文字 + 1 个小文件】', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 共 {len(hits)} 次 PreSend HIT，产物：callchain_trace_{ts}_*', flush=True)
    os._exit(0)


if __name__ == '__main__':
    main()
