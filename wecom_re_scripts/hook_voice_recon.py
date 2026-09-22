# hook_voice_recon.py — Phase A Voice recon
#
# 目的（回答 U1 / U2 / U3 / U4 里的 U3，为 U1/U2 铺路）：
#   1. TLS 门控 PreSendNewMessage，捕获"PC 转发已同步语音"的整次 send 窗口
#   2. 记录 PreSend 入参（ecx=this + [esp+4..+40]）→ 反推调用签名（U3）
#   3. SER (0x9f042a0) hit 时：
#      - 抓 this 2KB + arg0 16KB（voice envelope 可能远大于 text）
#      - 从 arg0 里扫描 voice 特征：.silk / .amr / aeskey / file_id / CDN URL / duration
#      - vtable 与 76-pool 交叉：命中 → 打印 idx 与 type_url；未命中 → ★TOP-LEVEL（更值得关注）
#   4. 所有 dump 落盘 runtime/wecom_re/voice_recon_<ts>_*.bin
#
# 使用：
#   1. 手机企微给 FTA 发 5-10s 语音
#   2. 确认 PC FTA 同步收到
#   3. python hook_voice_recon.py
#   4. 180s 窗口内：右键该语音 → 转发 → 选任意联系人（FTA/小号）→ 发送（1 次）
#   5. 分析 voice_recon_<ts>_*.bin

import frida, subprocess, sys, os, json, re, bisect
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 180
MAX_TOTAL = 80

# ── 目标 ──
PRESEND_RVA = 0x919ffb2          # PreSendNewMessage
V_SER       = 0x09f042a0         # SerializeWithCachedSizes (shared vfunc)
V_BYT       = 0x09f03c40         # ByteSizeLong (shared vfunc)

# ── 76-pool 加载（用于 vtable → type_url 识别）──
POOL_JSON = OUT_DIR / 'parse_typeurl_pool_20260914_122249.json'
POOL_LOOKUP = []
if POOL_JSON.exists():
    _pool = json.loads(POOL_JSON.read_text('utf-8'))['entries']
    for e in _pool:
        POOL_LOOKUP.append((e['entry_va'], e['type_url'], e['idx']))
    POOL_LOOKUP.sort()
    print(f'[*] 76-pool loaded: {len(POOL_LOOKUP)} entries')
else:
    print(f'[!] 76-pool json missing, vtable mapping disabled')

_POOL_VAS = [x[0] for x in POOL_LOOKUP]

def match_vtable(vt):
    """vtable → nearest pool entry within ±0x400. Returns (idx, type_url, delta) or None."""
    if not POOL_LOOKUP: return None
    i = bisect.bisect_right(_POOL_VAS, vt)
    best = None
    for j in (i-1, i):
        if 0 <= j < len(POOL_LOOKUP):
            va, name, idx = POOL_LOOKUP[j]
            d = vt - va
            if abs(d) <= 0x400:
                if best is None or abs(d) < abs(best[2]):
                    best = (idx, name, d)
    return best

# ── Voice 特征扫描 ──
VOICE_MARKERS = [
    b'.silk', b'.amr', b'SILK', b'#!SILK', b'aeskey', b'silk_url',
    b'voice_length', b'voiceid', b'file_id', b'vfid', b'msg.Voice',
    b'msg.SendVoice', b'AudioMsg', b'voice_id', b'silkmd5',
    b'cdnthumbaeskey', b'fileencrypt', b'md5', b'mediaid',
    b'ConvMessage', b'MessageBody', b'RichMessage',
]
CDN_HOSTS = [b'.wework.qq.com', b'wxwork.wxcdn', b'weworkcdn', b'.tencent-cloud',
             b'wework-file', b'wework.cdn', b'wework1251', b'wework.tencent']

def scan_voice_features(data: bytes, top_strings=60):
    out = {'markers': [], 'cdn_urls': [], 'ascii_strings': [], 'high_entropy_16': []}
    for m in VOICE_MARKERS:
        p = 0
        while True:
            p = data.find(m, p)
            if p < 0: break
            out['markers'].append({
                'marker': m.decode('latin-1'),
                'offset': p,
                'ctx': data[max(0,p-8):p+len(m)+48].hex(),
            })
            p += 1
            if len(out['markers']) > 40: break
    for h in CDN_HOSTS:
        p = 0
        while True:
            p = data.find(h, p)
            if p < 0: break
            s = data.rfind(b'http', max(0, p-120), p)
            end_nul = data.find(b'\x00', p+len(h))
            end_ws = data.find(b' ', p+len(h))
            e = min([x for x in (end_nul, end_ws, p+len(h)+256) if x > 0])
            piece = data[max(0, s if s>=0 else p-8):e].decode('latin-1', errors='replace')
            out['cdn_urls'].append({'offset': p, 'url': piece[:300]})
            p += 1
            if len(out['cdn_urls']) > 20: break
    # ASCII strings (>=6 printable)
    for m in re.finditer(rb'[\x20-\x7e]{6,}', data):
        out['ascii_strings'].append({'offset': m.start(), 's': m.group().decode('latin-1', errors='replace')})
        if len(out['ascii_strings']) >= top_strings: break
    # 高熵 16 字节候选（aeskey/md5 特征）— 简单粗筛：uniq_bytes >= 12 且非全 ASCII
    for off in range(0, len(data) - 16, 4):
        chunk = data[off:off+16]
        if len(set(chunk)) < 12: continue
        if all(0x20 <= b < 0x7f for b in chunk): continue  # 是字符串
        if chunk.count(0) > 2: continue
        out['high_entropy_16'].append({'offset': off, 'hex': chunk.hex()})
        if len(out['high_entropy_16']) >= 20: break
    return out

# ── Frida JS ──
JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(__PRESEND_RVA__);
var V_SER = ptr(__V_SER__);
var V_BYT = ptr(__V_BYT__);
var MAX_TOTAL = __MAX_TOTAL__;

function safeBytes(a, sz) {
    try {
        var p = (typeof a === 'number' || typeof a === 'string') ? ptr(a) : a;
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
function readU32(ab, i) { var a=new Uint8Array(ab); return ((a[i]|(a[i+1]<<8)|(a[i+2]<<16)|(a[i+3]<<24))>>>0); }

var WIN = {tid_state:{}, presend_cnt: 0};

Interceptor.attach(PRESEND, {
    onEnter: function(args){
        WIN.tid_state[this.threadId] = 1;
        WIN.presend_cnt++;
        var n = WIN.presend_cnt;
        var ecx = this.context.ecx.toUInt32();
        var esp = this.context.esp;
        // 抓栈 [esp+4..+40]（stdcall/thiscall 参数区）
        var stk = [];
        for (var i=0; i<10; i++) {
            try { stk.push('0x'+esp.add(4+i*4).readU32().toString(16)); } catch(e) { stk.push('?'); }
        }
        // dump this 512B (SendManager state)
        var this_hex = null;
        var raw = safeBytes(ecx, 512);
        if (raw) this_hex = toHex(raw);
        // dump arg0 = [esp+4]  4KB
        var arg0_v = 0, arg0_hex = null;
        try {
            arg0_v = esp.add(4).readU32();
            var raw2 = safeBytes(arg0_v, 4096);
            if (raw2) arg0_hex = toHex(raw2);
        } catch(e) {}
        send({t:'presend_enter', n:n, tid:this.threadId,
              ecx:'0x'+ecx.toString(16), esp:'0x'+esp.toUInt32().toString(16),
              stk:stk, arg0_addr:'0x'+arg0_v.toString(16),
              ret_addr:'0x'+this.returnAddress.toUInt32().toString(16),
              this_hex:this_hex, arg0_hex:arg0_hex});
    },
    onLeave: function(retval){
        delete WIN.tid_state[this.threadId];
        send({t:'presend_leave', n:WIN.presend_cnt, tid:this.threadId,
              retval:'0x'+retval.toUInt32().toString(16)});
    }
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
            var raw = safeBytes(this_v, 2048);
            if (!raw) return;
            var vtable = readU32(raw, 0);
            var hex_this = toHex(raw);

            var arg0_hex = null, arg0_v = 0;
            if (has_arg0) {
                arg0_v = args[0].toUInt32();
                var raw2 = safeBytes(arg0_v, 16384);   // ★ 16 KB
                if (raw2) arg0_hex = toHex(raw2);
            }

            send({
                t:'ser_hit', tag:tag, n:self.cnt, tid:this.threadId,
                this_addr:'0x'+this_v.toString(16),
                vtable:'0x'+vtable.toString(16),
                arg0_addr:'0x'+arg0_v.toString(16),
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
    raise RuntimeError('no wecom pid found (:9882 listener)')

hits, presends = [], []

def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')

    if t == 'ready':
        print('[+] voice recon hook ARMED. Waiting for PreSend...\n', flush=True); return

    if t == 'presend_enter':
        print(f'\n{"="*76}\n[PRESEND #{p["n"]}] ENTER  tid={p["tid"]}', flush=True)
        print(f'  ecx (this)   = {p["ecx"]}', flush=True)
        print(f'  esp          = {p["esp"]}', flush=True)
        print(f'  stk [esp+4..+40]:', flush=True)
        for i, s in enumerate(p['stk']):
            print(f'    +{4+i*4:02x} = {s}', flush=True)
        print(f'  arg0 addr    = {p["arg0_addr"]}', flush=True)
        print(f'  ret_addr     = {p["ret_addr"]}', flush=True)
        # dump this + arg0
        if p.get('this_hex'):
            fn = OUT_DIR / f'voice_recon_{ts}_presend{p["n"]}_this.bin'
            fn.write_bytes(bytes.fromhex(p['this_hex']))
            print(f'  ↳ this 512B → {fn.name}', flush=True)
        if p.get('arg0_hex'):
            b = bytes.fromhex(p['arg0_hex'])
            fn = OUT_DIR / f'voice_recon_{ts}_presend{p["n"]}_arg0.bin'
            fn.write_bytes(b)
            print(f'  ↳ arg0 4KB → {fn.name}', flush=True)
            feats = scan_voice_features(b, top_strings=30)
            if feats['markers']:
                print(f'  ★ arg0 voice markers:', flush=True)
                for m in feats['markers'][:8]:
                    print(f'      {m["marker"]!r} @+{m["offset"]:#x}', flush=True)
            if feats['cdn_urls']:
                print(f'  ★ arg0 CDN URLs:', flush=True)
                for u in feats['cdn_urls'][:3]:
                    print(f'      {u["url"][:180]!r}', flush=True)
        presends.append(p)
        return

    if t == 'presend_leave':
        print(f'[PRESEND #{p["n"]}] LEAVE  retval={p["retval"]}\n{"="*76}', flush=True); return

    if t == 'ser_hit':
        vt = int(p['vtable'], 16)
        m = match_vtable(vt)
        if m:
            label = f'★#{m[0]:02d}:{m[1]} (Δ{m[2]:+d})'
        else:
            label = '★TOP-LEVEL (not in 76-pool) ← 关注！'
        print(f'[{p["tag"]}] #{p["n"]:02d}  vt={p["vtable"]:>12}  {label}', flush=True)
        print(f'         this={p["this_addr"]}  arg0={p["arg0_addr"]}  ret={p["ret_addr"]}', flush=True)
        # dump
        vt_s = f'{vt:08x}'
        fn1 = OUT_DIR / f'voice_recon_{ts}_h{p["n"]:03d}_{p["tag"]}_vt{vt_s}_this.bin'
        fn1.write_bytes(bytes.fromhex(p['this_hex']))
        if p.get('arg0_hex'):
            b = bytes.fromhex(p['arg0_hex'])
            fn2 = OUT_DIR / f'voice_recon_{ts}_h{p["n"]:03d}_{p["tag"]}_vt{vt_s}_arg0.bin'
            fn2.write_bytes(b)
            feats = scan_voice_features(b, top_strings=20)
            if feats['markers']:
                for mk in feats['markers'][:5]:
                    print(f'         ★ marker {mk["marker"]!r} @+{mk["offset"]:#x}', flush=True)
            if feats['cdn_urls']:
                for u in feats['cdn_urls'][:2]:
                    print(f'         ★ CDN {u["url"][:150]!r}', flush=True)
            if feats['high_entropy_16']:
                # 只列前 3 个高熵块
                he = feats['high_entropy_16'][:3]
                print(f'         · high-entropy 16B (aeskey/md5 候选): {[h["hex"] for h in he]}', flush=True)
        hits.append({'tag': p['tag'], 'n': p['n'], 'vtable': p['vtable'],
                     'match': m, 'this': p['this_addr'], 'arg0': p['arg0_addr']})
        with (OUT_DIR/f'voice_recon_{ts}.ndjson').open('a', encoding='utf-8') as f:
            f.write(json.dumps({'tag': p['tag'], 'n': p['n'], 'vt': p['vtable'],
                                'match': m, 'this': p['this_addr'], 'arg0': p['arg0_addr']},
                               ensure_ascii=False)+'\n')

def main():
    js = (JS_TPL.replace('__PRESEND_RVA__', str(PRESEND_RVA))
                .replace('__V_SER__',       str(V_SER))
                .replace('__V_BYT__',       str(V_BYT))
                .replace('__MAX_TOTAL__',   str(MAX_TOTAL)))
    print('[*] finding PID …', flush=True)
    pid = get_pid()
    print(f'    PID = {pid}', flush=True)
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*76}')
    print(f'★★★  你有 {CAPTURE_SEC}s 时间 ★★★')
    print(f'  1. 确认 FTA 里能看到手机同步过来的那条语音')
    print(f'  2. 【右键该语音】→【转发】→ 选任意联系人 → 发送（只需 1 次）')
    print(f'  3. 观察下面的输出，主要看：')
    print(f'      · [PRESEND] ENTER 里的 stk 参数（U3）')
    print(f'      · [SER] 命中的 vtable label（★TOP-LEVEL = voice msg 类）')
    print(f'      · arg0 里的 marker / CDN / high-entropy 块（凭证组成）')
    print(f'{"="*76}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n{"="*76}\n[+] Recon 结束')
    print(f'    PreSend 事件数: {len(presends)}')
    print(f'    SER/BYT hits :  {len(hits)}')
    if presends and not hits:
        print(f'    ⚠️  PreSend 触发了但 SER 没触发 — 可能转发走了不同代码路径')
    if not presends:
        print(f'    ⚠️  180s 内 PreSend 没触发 — 检查：\n'
              f'         · 是否真的做了"转发"操作？\n'
              f'         · frida 是否 attach 到了正确 PID？\n'
              f'         · 是否命中了不同的 send 函数？')
    print(f'    产物：voice_recon_{ts}_*.bin  +  voice_recon_{ts}.ndjson', flush=True)
    os._exit(0)

if __name__ == '__main__':
    main()
