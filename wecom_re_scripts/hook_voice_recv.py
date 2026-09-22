# hook_voice_recv.py — 手机→PC voice 同步接收侧探测
#
# 策略：SER 全局 hook（NO PreSend gate），发现 recv 触发的新 vtable
# 已知 outbound top-level: 0xb0610c0 / 0xb06c9b8 / 0xb0656a8 / 0xb0901ac
# 期望：收 voice 时会出现"未见过"的 vtable，其 arg0 里含真 voice payload
#
# 用户操作：
#   1. 手机企微给 FTA 发一条"清晰易识别"的语音（时长 6-15 秒）
#   2. 语音**内容里说出"VOICERECON001"或类似记号词**（便于后续查证）
#   3. 等 PC FTA 出现气泡
#   完事 60s 自动收工

import frida, subprocess, sys, os, json, re
from pathlib import Path
from datetime import datetime
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 60
MAX_PER_VT = 4          # 每 vtable 最多 dump 4 次，防止爆盘

V_SER = 0x09f042a0
KNOWN_OUTBOUND = {0xb0610c0, 0xb06c9b8, 0xb0656a8, 0xb0901ac}

# 76-pool 已知 vtables → 加载后用于识别
POOL_JSON = OUT_DIR / 'parse_typeurl_pool_20260914_122249.json'
POOL_MAP = {}
if POOL_JSON.exists():
    for e in json.loads(POOL_JSON.read_text('utf-8'))['entries']:
        POOL_MAP[e['entry_va']] = (e['idx'], e['type_url'])
print(f'[*] 76-pool loaded: {len(POOL_MAP)} entries')

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var V_SER = ptr(__V_SER__);
var MAX_PER_VT = __MAX_PER_VT__;

function safeBytes(a, sz) {
    try { var p = (typeof a === 'number') ? ptr(a) : a;
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

var VT_HIT_CNT = {};
var TOTAL = 0;

Interceptor.attach(V_SER, {
    onEnter: function(args) {
        TOTAL++;
        var this_v;
        try { this_v = this.context.ecx.toUInt32(); } catch(e) { return; }
        var raw_head = safeBytes(this_v, 4);
        if (!raw_head) return;
        var vtable = readU32(raw_head, 0);
        var key = '0x'+vtable.toString(16);
        VT_HIT_CNT[key] = (VT_HIT_CNT[key] || 0) + 1;
        if (VT_HIT_CNT[key] > MAX_PER_VT) return;

        var raw_this = safeBytes(this_v, 1024);
        var arg0_v = args[0].toUInt32();
        var raw_arg0 = safeBytes(arg0_v, 8192);
        send({
            t:'ser', tid:this.threadId, n:VT_HIT_CNT[key],
            vtable:key, this_addr:'0x'+this_v.toString(16),
            arg0_addr:'0x'+arg0_v.toString(16),
            ret_addr:'0x'+this.returnAddress.toUInt32().toString(16),
            this_hex: raw_this ? toHex(raw_this) : null,
            arg0_hex: raw_arg0 ? toHex(raw_arg0) : null,
        });
    }
});
rpc.exports.stats = function() { return {total: TOTAL, vt: VT_HIT_CNT}; };
send({t:'ready'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

hits = []
per_vt = Counter()

def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')
    if t == 'ready':
        print('[+] recv hook ARMED (SER no-gate)', flush=True); return
    if t != 'ser': return
    vt = int(p['vtable'], 16)
    per_vt[vt] += 1
    is_known = vt in KNOWN_OUTBOUND
    pool_hit = POOL_MAP.get(vt)
    tag = ''
    if is_known: tag = '[OLD-outbound]'
    elif pool_hit: tag = f'[POOL #{pool_hit[0]}:{pool_hit[1]}]'
    else: tag = '[★NEW]'
    # 只详细打印 NEW，其它压缩到 stats
    if not is_known and per_vt[vt] <= 2:
        print(f'{tag}  vt={p["vtable"]:>12}  n={p["n"]}  this={p["this_addr"]}  arg0={p["arg0_addr"]}  ret={p["ret_addr"]}', flush=True)
    # dump
    fp = OUT_DIR / f'voice_recv_{ts}_vt{vt:08x}_n{p["n"]}_arg0.bin'
    if p.get('arg0_hex'):
        b = bytes.fromhex(p['arg0_hex'])
        fp.write_bytes(b)
        # 立刻挖 voice 特征
        markers = []
        for m in [b'.silk', b'.amr', b'SILK', b'aeskey', b'file_id', b'voice_id',
                  b'magiccube', b'rtxapp', b'wework-file', b'wwmedia', b'duration',
                  b'silk_url', b'voice_length', b'cdn_url', b'mediaid']:
            if m in b: markers.append(m.decode('latin-1'))
        # 明文短语音"say something"检查
        for kw in [b'VOICE', b'RECON', b'silk', b'.mp3', b'.amr']:
            if kw in b: markers.append(f'kw:{kw.decode("latin-1")}')
        if markers:
            print(f'    ★ {fp.name}  markers: {markers}', flush=True)
    if p.get('this_hex'):
        fp2 = OUT_DIR / f'voice_recv_{ts}_vt{vt:08x}_n{p["n"]}_this.bin'
        fp2.write_bytes(bytes.fromhex(p['this_hex']))
    hits.append({'vt': p['vtable'], 'n': p['n'], 'is_known': is_known,
                 'pool': pool_hit, 'this': p['this_addr'], 'arg0': p['arg0_addr']})

def main():
    pid = get_pid(); print(f'[*] PID={pid}')
    sess = frida.get_local_device().attach(pid)
    js = (JS_TPL.replace('__V_SER__', str(V_SER))
                .replace('__MAX_PER_VT__', str(MAX_PER_VT)))
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*76}')
    print(f'★★★ 你有 {CAPTURE_SEC}s ★★★')
    print(f'   1. 手机给 FTA 发 1 条语音（6-15 秒，内容包含 "VOICERECON001" 便于查证）')
    print(f'   2. 等 PC FTA 收到气泡（能播放）')
    print(f'   3. 什么都别在 PC 上操作')
    print(f'{"="*76}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try:
        stats = sc.exports_sync.stats()
    except Exception:
        stats = {'total': 0, 'vt': {}}
    try: sc.unload(); sess.detach()
    except Exception: pass

    print(f'\n{"="*76}\n[+] 收工')
    print(f'    SER 总触发数（含未 dump）: {stats.get("total", 0)}')
    print(f'    独立 vtable 数: {len(per_vt)}')
    print(f'    Dump 落盘: {len(hits)}')
    print(f'\n{"─"*76}\n★ 按 hit 数排序（★NEW = 从未见过；候选 recv-side）：')
    all_vts = stats.get('vt', {})
    all_vts = {int(k,16) if isinstance(k, str) else k: v for k, v in all_vts.items()}
    for vt, n in sorted(all_vts.items(), key=lambda kv: -kv[1])[:40]:
        tag = ''
        if vt in KNOWN_OUTBOUND: tag = '[OLD-outbound]'
        elif vt in POOL_MAP: tag = f'[POOL #{POOL_MAP[vt][0]}:{POOL_MAP[vt][1][:32]}]'
        else: tag = '[★NEW]'
        print(f'    vt=0x{vt:08x}  hits={n:>4}  {tag}')

    print(f'\n    产物: voice_recv_{ts}_vt*.bin')
    os._exit(0)

if __name__ == '__main__': main()
