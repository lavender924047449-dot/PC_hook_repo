# hook_top_candidates.py — 精选 9 个候选 fn，dump 完整 args + this（1KB 每个）
# 目的：从 3 条链 A/B/C 的 d3/d4/d5 里，锁死 ConstructMessageProtobuf
# 判定：arg dump 里同时出现（a）conv_id "FILEASSIST" 或 std::string @+0x13c 结构
#                                （b）protobuf 字节流首字节合法 tag（0x0A/0x08/0x12/0x1A…）

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90
MAX_HITS_PER_FN = 4

CANDIDATES = [
    # (rva, tag, chain, depth)
    (0x0919eaa0, 'A_d1_root',          'A', 1),
    (0x0992c100, 'A_d3',               'A', 3),
    (0x09ba6287, 'A_d4',               'A', 4),
    (0x09ba5b3d, 'A_d5_leaf(md5)',     'A', 5),
    (0x07ce8120, 'B_d4',               'B', 4),
    (0x09bc1db8, 'B_d5(SendMsgPerf)',  'B', 5),
    (0x09926cc0, 'C_d4',               'C', 4),
    (0x09926c00, 'C_d5(BeginSendMsg)', 'C', 5),
    (0x09ba54f0, 'X_d1(top pb wrap)',  'X', 1),
]

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var BASE = mod.base;
var PRESEND = BASE.add(0x919ffb2);
var CANDS = __CANDS__;
var MAX_HITS = __MAX_HITS__;

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
function asciiStrs(ab, minLen) {
    minLen = minLen || 4;
    var a = new Uint8Array(ab), out=[], run='', st=0;
    for (var i=0;i<a.length;i++) {
        if (a[i]>=0x20 && a[i]<=0x7E) { if (!run.length) st=i; run += String.fromCharCode(a[i]); }
        else { if (run.length>=minLen) out.push({o:st,s:run}); run=''; }
    }
    if (run.length>=minLen) out.push({o:st,s:run});
    return out;
}
// 检查 buffer 是否含 conv_id "FILEASSIST"
function hasFileassist(hex) { return hex.indexOf('46494c45415353495354') !== -1; }
// 提取前几个 pb tag：{field,wt}
function firstTags(ab) {
    var a = new Uint8Array(ab), out=[], i=0;
    for (var k=0; k<12 && i<a.length; k++) {
        var v=0, sh=0, ok=false, st=i;
        while (i<a.length && i-st<5) { var b=a[i++]; v |= (b&0x7f)<<sh; sh+=7; if (!(b&0x80)) {ok=true;break;} }
        if (!ok) break;
        var wt=v&7, f=v>>>3;
        if (f===0 || f>200 || wt===3 || wt===4 || wt>5) break;
        out.push({f:f, wt:wt});
        // skip payload
        if (wt===0) { while (i<a.length && (a[i]&0x80)) i++; i++; }
        else if (wt===1) i+=8;
        else if (wt===5) i+=4;
        else if (wt===2) {
            var L=0,sh2=0,st2=i;
            while (i<a.length && i-st2<5) { var bb=a[i++]; L|=(bb&0x7f)<<sh2; sh2+=7; if (!(bb&0x80)) break; }
            if (L>ab.byteLength) { L=Math.min(ab.byteLength-i, 64); }
            i += L;
        }
    }
    return out;
}

// TLS 窗口
var WIN = {tid_state: {}};
var hit_cnt = 0;

Interceptor.attach(PRESEND, {
    onEnter: function(args) {
        if (hit_cnt >= MAX_HITS) return;
        this._tid = this.threadId; this._active = true;
        WIN.tid_state[this._tid] = this;
        this._hits = [];
        // dump PreSend 自己的 args[1] head 128B for reference
        try {
            var mo = args[1].toUInt32();
            this._presend_arg1 = mo;
        } catch(e){}
    },
    onLeave: function(retval) {
        if (!this._active) return;
        hit_cnt++;
        delete WIN.tid_state[this._tid];
        send({t:'presend_done', n:hit_cnt, tid:this._tid,
              presend_arg1: this._presend_arg1,
              hits: this._hits});
    }
});

// 每候选独立计数
var fn_cnt = {};
CANDS.forEach(function(c){
    var rva = c[0], tag = c[1], chain = c[2], depth = c[3];
    var addr = BASE.add(rva);
    fn_cnt[rva] = 0;
    try {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var pst = WIN.tid_state[this.threadId];
                if (!pst) return;
                if (fn_cnt[rva] >= 24) return;   // MAX_HITS_PER_FN * MAX_HITS = 4*6
                fn_cnt[rva]++;
                // dump args[0..5] + ecx + esp[0..3] each 1024B
                var dumps = {};
                for (var i=0;i<6;i++) {
                    var v = args[i].toUInt32();
                    var raw = safeBytes(v, 1024);
                    if (raw) {
                        dumps['a'+i] = {
                            addr: '0x'+v.toString(16),
                            hex: toHex(raw),
                            strs: asciiStrs(raw,4).slice(0,10),
                            tags: firstTags(raw),
                            fa: hasFileassist(toHex(raw))
                        };
                    } else {
                        dumps['a'+i] = {addr:'0x'+v.toString(16), null:true};
                    }
                }
                // ecx (thiscall)
                try {
                    var ecxv = this.context.ecx.toUInt32();
                    var raw = safeBytes(ecxv, 1024);
                    if (raw) {
                        dumps['ecx'] = {addr:'0x'+ecxv.toString(16), hex: toHex(raw),
                            strs: asciiStrs(raw,4).slice(0,10),
                            tags: firstTags(raw), fa: hasFileassist(toHex(raw))};
                    }
                } catch(e){}
                pst._hits.push({
                    rva: rva, tag: tag, chain: chain, depth: depth,
                    seq: pst._hits.length,
                    ret_addr: '0x'+this.returnAddress.toUInt32().toString(16),
                    d: dumps
                });
            }
        });
    } catch(e) {}
});

send({t:'ready', n_cands: CANDS.length});
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
    if t=='ready': print(f'[+] hooks armed: {p["n_cands"]} candidates', flush=True); return
    if t!='presend_done': return
    hits.append(p)
    with (OUT_DIR/f'hook_top_{ts}.ndjson').open('a', encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    print(f'\n{"="*72}\n★ PreSend HIT #{p["n"]}  presend_arg1=0x{p["presend_arg1"]:x}  cand hits={len(p["hits"])}', flush=True)
    for h in p['hits']:
        # 每个候选打印 args 摘要
        print(f'  [{h["chain"]}/d{h["depth"]}] {h["tag"]:24}  0x{h["rva"]:08x}  ret={h["ret_addr"]}', flush=True)
        for k, d in h['d'].items():
            if d.get('null'): continue
            tags_str = ','.join(f'f{t["f"]}w{t["wt"]}' for t in d.get('tags',[])[:6])
            fa = '★FA' if d.get('fa') else ''
            strs_prev = ','.join(s['s'][:20] for s in d.get('strs',[])[:2])
            print(f'      {k:>3} {d["addr"]}  tags=[{tags_str}] {fa}  {strs_prev}', flush=True)
        # 每候选 args 单独落盘（前 512B）
        for k, d in h['d'].items():
            if d.get('null') or not d.get('hex'): continue
            fn = OUT_DIR / f'hook_top_{ts}_h{p["n"]}_{h["tag"].replace("/","_").replace("(","").replace(")","")}_{k}.bin'
            fn.write_bytes(bytes.fromhex(d['hex']))

def main():
    js = JS_TPL.replace('__CANDS__', json.dumps([list(c) for c in CANDIDATES])) \
               .replace('__MAX_HITS__', '6')
    print('[*] PID …', flush=True); pid = get_pid(); print(f'    PID={pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*72}\n★★★ 请在 {CAPTURE_SEC}s 内 在企微【向 FTA 发 1 条文字 + 1 个小文件】', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 共 {len(hits)} 次 HIT，产物：hook_top_{ts}_*', flush=True)
    os._exit(0)

if __name__ == '__main__': main()
