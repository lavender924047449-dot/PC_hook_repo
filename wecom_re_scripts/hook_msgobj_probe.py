# hook_msgobj_probe.py — 摸 MessageObject 结构
#
# 目的：dump PreSendNewMessage 的 [esp+18] = MessageObject heap 结构
#       找到 msgtype 字段偏移，为下一步 patch 做准备
#
# 参考现有 hook_voice_recon.py 已知：
#   - ecx = SendManager 单例 (0x2bba00b4)
#   - [esp+04] = stack retbuf (已 dump 过)
#   - [esp+18] = ★★★ MessageObject heap 指针 (本次目标)
#   - [esp+14] / [esp+1c] = 两个 code addr (callback?)
#
# 使用：
#   1. python hook_msgobj_probe.py
#   2. 60s 内 你右键 FTA 任意语音消息 → 转发 → 发给小号
#   3. 抓 MessageObject 3KB dump

import frida, subprocess, sys, os, json, re, struct
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
CAPTURE_SEC = 90

PRESEND_RVA = 0x919ffb2

JS_TPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var PRESEND = mod.base.add(__PRESEND_RVA__);

function safeBytes(a, sz) {
    try {
        var p = (typeof a === 'number') ? ptr(a) : a;
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

var CNT = 0;
Interceptor.attach(PRESEND, {
    onEnter: function(args){
        CNT++;
        var esp = this.context.esp;
        var ecx = this.context.ecx.toUInt32();
        var stk = {};
        for (var i=0; i<11; i++) {
            try { stk['+'+(4+i*4).toString(16)] = '0x'+esp.add(4+i*4).readU32().toString(16); }
            catch(e) { stk['+'+(4+i*4).toString(16)] = '?'; }
        }
        // ★ dump [esp+18] = MessageObject
        var msgobj_v = 0, msgobj_hex = null;
        try {
            msgobj_v = esp.add(0x18).readU32();
            var raw = safeBytes(msgobj_v, 3072);   // 3KB
            if (raw) msgobj_hex = toHex(raw);
        } catch(e) {}
        // 顺便再 dump 几个可能 heap arg
        var extra = {};
        for (var slot of [0x08, 0x0c, 0x10, 0x1c, 0x28]) {
            try {
                var pv = esp.add(slot).readU32();
                if (pv > 0x100000 && pv < 0x7F000000) {
                    var r = safeBytes(pv, 512);
                    if (r) extra['esp+'+slot.toString(16)] = toHex(r);
                }
            } catch(e) {}
        }
        send({t:'presend', n:CNT, tid:this.threadId,
              ecx:'0x'+ecx.toString(16), esp:'0x'+esp.toUInt32().toString(16),
              stk:stk, msgobj_addr:'0x'+msgobj_v.toString(16),
              msgobj_hex: msgobj_hex, extra: extra});
    }
});
send({t:'ready'});
"""

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

def analyze_msgobj(data):
    """启发式找 msgtype 字段（小 uint32 值 in [1..256]）"""
    out = []
    for off in range(0, min(len(data)-4, 256), 4):
        v = struct.unpack('<I', data[off:off+4])[0]
        if 1 <= v <= 256:
            out.append((off, v))
    return out

def dump_hex(data, per_line=16, max_lines=48):
    lines = []
    for i in range(0, min(len(data), per_line*max_lines), per_line):
        chunk = data[i:i+per_line]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        ascs = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append(f'  +{i:04x}  {hexs:<48}  {ascs}')
    return lines

hits = []
def on_msg(m, d):
    if m.get('type')=='error':
        print(f'[ERR] {m.get("description","")[:400]}', flush=True); return
    if m.get('type')!='send': return
    p = m['payload']; t = p.get('t')
    if t == 'ready':
        print('[+] msgobj probe ARMED', flush=True); return
    if t != 'presend': return
    print(f'\n{"="*76}\n[PRESEND #{p["n"]}] tid={p["tid"]}  ecx={p["ecx"]}')
    print(f'  stk: {p["stk"]}')
    print(f'  msgobj_addr = {p["msgobj_addr"]}')
    if p.get('msgobj_hex'):
        b = bytes.fromhex(p['msgobj_hex'])
        fn = OUT_DIR / f'msgobj_probe_{ts}_n{p["n"]}.bin'
        fn.write_bytes(b)
        print(f'  ↳ msgobj 3KB → {fn.name}')
        # 分析小 int 字段（msgtype 候选）
        cands = analyze_msgobj(b)
        print(f'  ── 小 uint32 候选（msgtype 可能位置）──')
        for off, v in cands[:20]:
            print(f'      +{off:04x} = {v}')
        # 头部 hex dump
        print(f'  ── header 前 256B ──')
        for line in dump_hex(b, per_line=16, max_lines=16):
            print(line)
    for k, hex in p.get('extra', {}).items():
        b = bytes.fromhex(hex)
        fn = OUT_DIR / f'msgobj_probe_{ts}_n{p["n"]}_extra_{k.replace("+","p")}.bin'
        fn.write_bytes(b)
        cands = analyze_msgobj(b[:256])
        print(f'  extra {k}: 512B → {fn.name}  small-int-cands: {[(hex(o), v) for o,v in cands[:8]]}')
    hits.append(p)

def main():
    pid = get_pid(); print(f'[*] PID={pid}')
    js = JS_TPL.replace('__PRESEND_RVA__', str(PRESEND_RVA))
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(js); sc.on('message', on_msg); sc.load()
    import time
    print(f'\n{"="*76}\n★★★ 你有 {CAPTURE_SEC}s ★★★')
    print(f'   右键 FTA 里任意一条语音 → 转发 → 发给小号 (1 次即可)')
    print(f'{"="*76}\n', flush=True)
    time.sleep(CAPTURE_SEC)
    try: sc.unload(); sess.detach()
    except Exception: pass
    print(f'\n[+] 收工. PreSend hits = {len(hits)}', flush=True)
    os._exit(0)

if __name__ == '__main__': main()
