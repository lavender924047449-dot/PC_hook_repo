# read_fwd_buf.py
# Hook 0x390CE0，读 args[1] 缓冲区实际字节
# Phase1 建基线，Phase2 捕获转发时的 buffer

import frida, subprocess, sys, os, time, json, threading
from pathlib import Path
from datetime import datetime
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
var wxBase = wx.base;
var FUNC_RVA = 0x390ce0;

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

var startTs = Date.now();
var phase = 1;
var records = [];
var hitCount = 0;
var MAX = 300;

Interceptor.attach(wxBase.add(FUNC_RVA), {
    onEnter: function(args) {
        if (hitCount >= MAX) return;
        var elapsed = Date.now() - startTs;
        
        // args[0]=0xffffffff, args[1]=begin, args[2]=end, args[3]=const
        var begin = args[1].toInt32() >>> 0;
        var end   = args[2].toInt32() >>> 0;
        var bufSize = (end > begin && end - begin < 1024) ? (end - begin) : 0;
        
        var buf = null;
        if (bufSize > 0) {
            buf = safeR(begin, Math.min(bufSize, 64));
        }
        
        // 读 args[4] 和 args[5]（可能是 this 或其他对象）
        var a4 = args[4].toInt32() >>> 0;
        var a5 = args[5].toInt32() >>> 0;
        var a4_bytes = safeR(a4, 16);
        
        var rec = {
            phase: phase,
            elapsed: elapsed,
            begin: '0x' + begin.toString(16),
            bufSize: bufSize,
            buf: buf,
            a4: '0x' + a4.toString(16),
            a5: '0x' + a5.toString(16),
            a4_bytes: a4_bytes
        };
        
        records.push(rec);
        hitCount++;
        
        if (buf) {
            var hexPrefix = buf.slice(0,8).map(b => ('0'+b.toString(16)).slice(-2)).join('');
            send({t:'hit', phase:phase, elapsed:elapsed, begin:rec.begin, size:bufSize, hex:hexPrefix});
        }
    }
});

send({t:'ready'});
recv('phase2', function(_) { phase = 2; send({t:'ack_phase', v:2}); });
recv('dump', function(_) { send({t:'dump', records:records}); });
"""

ready_event = threading.Event()
ack_event = threading.Event()
dump_event = threading.Event()
all_recs = []

def on_msg(msg, data):
    if msg.get('type') == 'error': print(f'ERR: {msg.get("description","")}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'ready': ready_event.set()
    elif t == 'ack_phase': ack_event.set()
    elif t == 'hit':
        ph = '[B]' if p['phase']==1 else '[F]'
        print(f'  {ph} t={p["elapsed"]/1000:.1f}s begin={p["begin"]} sz={p["size"]} hex={p["hex"]}')
    elif t == 'dump':
        all_recs.extend(p.get('records',[]))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
ready_event.wait(10)

print('\n[Phase 1] 8s 基线...')
time.sleep(8)

print('\n' + '='*60)
print('*** 请立即在企微转发一条消息！ ***')
print('='*60)
sc.post({'type':'phase2'})
ack_event.wait(5)

time.sleep(20)

sc.post({'type':'dump'})
dump_event.wait(10)

# ── 分析 ──
base_recs = [r for r in all_recs if r['phase']==1]
fwd_recs  = [r for r in all_recs if r['phase']==2]

def hex8(r):
    buf = r.get('buf')
    if not buf: return '?'
    return bytes(buf[:8]).hex()

base_hexes = Counter(hex8(r) for r in base_recs)
fwd_hexes  = Counter(hex8(r) for r in fwd_recs)

print(f'\n[结果]')
print(f'  基线调用: {len(base_recs)} 次，{len(base_hexes)} 种 buf 模式')
print(f'  转发窗口: {len(fwd_recs)} 次，{len(fwd_hexes)} 种 buf 模式')

print(f'\n  基线 buf 前8字节 Top5:')
for h, cnt in base_hexes.most_common(5):
    print(f'    {h}  x{cnt}')

print(f'\n  转发窗口 buf 前8字节（标注新出现）:')
for h, cnt in fwd_hexes.most_common(10):
    new = '  ★NEW' if h not in base_hexes else ''
    print(f'    {h}  x{cnt}{new}')

new_patterns = {h: cnt for h, cnt in fwd_hexes.items() if h not in base_hexes}
if new_patterns:
    print(f'\n  ★ 新模式详情:')
    for h in new_patterns:
        matching = [r for r in fwd_recs if hex8(r)==h]
        for r in matching[:2]:
            buf = r.get('buf', [])
            full = bytes(buf).hex() if buf else '?'
            a4b  = r.get('a4_bytes', [])
            a4h  = bytes(a4b).hex() if a4b else '?'
            print(f'    buf={full}')
            print(f'    a4_bytes={a4h}')

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'fwd_buf_{ts}.json'
out.write_text(json.dumps(all_recs, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

sc.unload()
sess.detach()
os._exit(0)
