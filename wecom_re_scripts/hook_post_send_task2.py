# hook_post_send_task2.py — 第十三轮成果收尾
# ------------------------------------------------------------------
# Hook 函数入口 RVA 0x3ebeb0 (from disasm)
#   * thiscall: ecx = this (PostSendMessageTask2*)
#   * 里面调用 0x3ebf6c → log helper (fmt=post_send_message_task2.cpp)
# 输出：每次命中 dump this[0..256]，逐 dword 尝试 deref 成字符串
# 目标：拿到 conversationId ("S:1688855042791155_...") + msgId + ClientId
# ------------------------------------------------------------------
import frida, subprocess, sys, os, time, json
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = datetime.now().strftime('%Y%m%d_%H%M%S')
DUMP = OUT / f'post_send_task2_{TS}.json'
SENTINEL = OUT / '_post_send_done.flag'
if SENTINEL.exists(): SENTINEL.unlink()

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('no :9882')

pid = get_pid()
print(f'PID = {pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
var RVA = 0x3ebeb0;
var TARGET = base.add(RVA);
send({t:'ready', base: base.toString(), target: TARGET.toString()});

function tryReadStr(v) {
    if (v < 0x10000 || v >= 0xF0000000) return null;
    try {
        var p = ptr(v);
        var bytes = new Uint8Array(p.readByteArray(256));
        if (bytes.length < 3) return null;
        var b0 = bytes[0], b1 = bytes[1];
        if (b0 >= 0x20 && b0 < 0x7f && b1 === 0 && bytes.length > 6 &&
            bytes[3] === 0 && bytes[5] === 0) {
            var s = '';
            for (var i = 0; i < 256; i += 2) {
                var c = bytes[i] | (bytes[i+1] << 8);
                if (c === 0) break;
                if (c < 0x20 || c > 0x7e) { if (i < 6) return null; break; }
                s += String.fromCharCode(c);
            }
            return s.length >= 3 ? '[U16]' + s : null;
        }
        if (b0 < 0x20 || b0 > 0x7e) return null;
        var end = 0;
        while (end < 256 && bytes[end] >= 0x20 && bytes[end] < 0x7f) end++;
        if (end < 4) return null;
        var s2 = '';
        for (var i = 0; i < end; i++) s2 += String.fromCharCode(bytes[i]);
        return s2;
    } catch(e) { return null; }
}

var cnt = 0;
Interceptor.attach(TARGET, {
    onEnter: function(args) {
        cnt++;
        try {
            var thisPtr = this.context.ecx;
            var thisVal = thisPtr.toUInt32();
            var frame = {
                n: cnt, ts: Date.now(),
                thisPtr: '0x' + thisVal.toString(16),
                fields: []
            };
            // Dump this[0..256] 每 4 字节
            for (var off = 0; off < 256; off += 4) {
                var v = 0;
                try { v = thisPtr.add(off).readU32() >>> 0; }
                catch(e) { break; }
                var e = {off: off, v: '0x' + v.toString(16)};
                var s1 = tryReadStr(v);
                if (s1) e.str = s1;
                // std::string SBO / 字符串对象一般 4~28 字节，内部 ptr 在 offset 0 or 0x10
                if (v > 0x10000 && v < 0xF0000000) {
                    try {
                        var d = ptr(v).readU32() >>> 0;
                        var s2 = tryReadStr(d);
                        if (s2) e.dstr = s2;
                    } catch(e2) {}
                }
                frame.fields.push(e);
            }
            // 读 vtable 前 8 项（this[0] = vtable ptr）
            var vt = thisPtr.readU32() >>> 0;
            frame.vtable = '0x' + vt.toString(16);
            var vtEntries = [];
            for (var i = 0; i < 8; i++) {
                try {
                    var f = ptr(vt).add(i*4).readU32() >>> 0;
                    vtEntries.push('0x' + f.toString(16));
                } catch(e) { break; }
            }
            frame.vt_entries = vtEntries;
            send({t:'hit', f: frame});
        } catch(e) {
            send({t:'err', msg: e.message});
        }
    }
});
recv('bye', function(_) { send({t:'bye', cnt: cnt}); });
"""

hits = []
ready = [False]
bye_ok = [False]

def on_msg(m, d):
    if m.get('type')=='error':
        print('ERR:', m.get('description')); return
    if m.get('type')!='send': return
    p = m['payload']
    if p.get('t')=='ready':
        ready[0]=True
        print(f'[+] ready base={p["base"]} target={p["target"]}')
    elif p.get('t')=='hit':
        f = p['f']
        hits.append(f)
        print(f'\n★ HIT #{f["n"]}  this={f["thisPtr"]}  vtable={f["vtable"]}')
        for e in f['fields']:
            marks = []
            if 'str' in e: marks.append(f'STR={e["str"][:120]!r}')
            if 'dstr' in e: marks.append(f'*STR={e["dstr"][:120]!r}')
            if marks:
                print(f'   [this+{e["off"]:03x}] {e["v"]}  {"  ".join(marks)}')
        print(f'   vtable[0..8]: {f["vt_entries"]}')
    elif p.get('t')=='err':
        print(f'[JS ERR] {p.get("msg")}')
    elif p.get('t')=='bye':
        print(f'[BYE] total onEnter = {p["cnt"]}')
        bye_ok[0]=True

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)
if not ready[0]:
    print('[!] not ready'); sys.exit(1)

print('\n' + '='*72)
print('>>> 现在请在企微中转发 2 次：')
print('>>>   Round A: 转发到 FTA（自己）')
print('>>>   Round B: 转发到任意外部联系人')
print(f'>>> 完成后 New-Item {SENTINEL.name} 触发结束')
print('>>> 最长 10 分钟')
print('='*72 + '\n')

t0=time.time()
last_hb=t0
while not SENTINEL.exists() and time.time()-t0 < 10*60:
    time.sleep(0.5)
    if time.time()-last_hb > 30:
        last_hb=time.time()
        print(f'  [hb] elapsed={int(time.time()-t0)}s hits={len(hits)}')

if SENTINEL.exists():
    try: SENTINEL.unlink()
    except: pass
    print(f'\n[+] sentinel received ({time.time()-t0:.1f}s)')

sc.post({'type':'bye'})
tw=time.time()
while not bye_ok[0] and time.time()-tw<3:
    time.sleep(0.1)

DUMP.write_text(json.dumps({'pid':pid,'ts':TS,'hits':hits}, ensure_ascii=False, indent=2),
                encoding='utf-8')
print(f'\n[+] saved: {DUMP.name}')
print(f'[+] total hits: {len(hits)}')
sc.unload(); sess.detach()
os._exit(0)
