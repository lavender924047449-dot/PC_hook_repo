# wsasend_fwd_bt.py
# Hook ws2_32.WSASend，在用户转发时捕获调用栈
# 找到新版 WXWork 中转发的真实 CGI 函数 RVA

import frida, subprocess, sys, os, time, json, threading
from datetime import datetime
from pathlib import Path

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
var wxEnd  = wxBase.add(wx.size);
send({t:'base', lo: wxBase.toString(), hi: wxEnd.toString()});

// 找 WSASend
var wsaSend = null;
var ws2 = Process.getModuleByName('ws2_32.dll');
var exports = ws2.enumerateExports();
for (var i = 0; i < exports.length; i++) {
    if (exports[i].name === 'WSASend') {
        wsaSend = exports[i].address;
        break;
    }
}
if (!wsaSend) { send({t:'fail', m:'WSASend not found'}); }
else { send({t:'info', m:'WSASend @ ' + wsaSend.toString()}); }

var startTs = Date.now();
var captures = [];
var hitCount = 0;
var MAX = 20;

function addrInWx(a) {
    return a.compare(wxBase) >= 0 && a.compare(wxEnd) < 0;
}

// 基线 WSASend 调用特征（无转发时）
var baselineBt0 = {};  // first-WXWork-frame -> count
var phase = 1;  // 1=baseline, 2=forward

Interceptor.attach(wsaSend, {
    onEnter: function(args) {
        // args: SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, ...
        var elapsed = Date.now() - startTs;
        var socket = args[0].toInt32();
        
        // 读 buffer
        var bufLen = 0;
        var bufHex = '';
        try {
            var lpBuffers = args[1];
            // WSABUF: {ULONG len, CHAR* buf}
            bufLen = lpBuffers.readU32();
            if (bufLen > 0 && bufLen < 65536) {
                var bufPtr = lpBuffers.add(4).readPointer();
                var data = new Uint8Array(bufPtr.readByteArray(Math.min(bufLen, 64)));
                bufHex = Array.from(data).map(b => ('0'+b.toString(16)).slice(-2)).join('');
            }
        } catch(e) {}

        // 获取 backtrace（仅 WXWork 内部帧）
        var bt = [];
        try {
            var frames = Thread.backtrace(this.context, Backtracer.FUZZY);
            for (var i = 0; i < frames.length && bt.length < 8; i++) {
                if (addrInWx(frames[i])) {
                    var rva = frames[i].sub(wxBase).toUInt32();
                    bt.push('0x' + rva.toString(16));
                }
            }
        } catch(e) {}

        if (hitCount >= MAX) return;
        hitCount++;

        var record = {phase:phase, elapsed:elapsed, socket:socket, bufLen:bufLen, buf:bufHex, bt:bt};
        captures.push(record);

        // 实时打印
        send({t:'ws', elapsed:elapsed, phase:phase, bufLen:bufLen, buf:bufHex.slice(0,16), bt:bt.slice(0,3)});
    }
});
send({t:'ready'});

recv('phase2', function(_) { phase = 2; send({t:'ack', phase:2}); });
recv('dump',   function(_) { send({t:'dump', caps:captures}); });
"""

all_caps = []
ready_event = threading.Event()
ack_event = threading.Event()
dump_event = threading.Event()

def on_msg(msg, data):
    if msg.get('type') == 'error': print(f'ERR: {msg.get("description","")}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'base': print(f'  wxBase={p["lo"]} ~ {p["hi"]}')
    elif t == 'info': print(f'  {p["m"]}')
    elif t == 'fail': print(f'  [FAIL] {p["m"]}')
    elif t == 'ready': ready_event.set()
    elif t == 'ack': ack_event.set()
    elif t == 'ws':
        ph = '[BASE]' if p['phase']==1 else '[FWD!]'
        print(f'  {ph} t={p["elapsed"]/1000:.1f}s len={p["bufLen"]} buf={p["buf"]} bt={p["bt"]}')
    elif t == 'dump':
        all_caps.extend(p.get('caps', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
ready_event.wait(10)

print('\n[Phase 1] 10s 基线观察 WSASend...')
time.sleep(10)

print('\n' + '='*60)
print('*** 请立即在企微转发一条消息！***')
print('='*60)
sc.post({'type':'phase2'})
ack_event.wait(5)

time.sleep(20)

# Dump
sc.post({'type':'dump'})
dump_event.wait(10)

# 分析
base_caps = [c for c in all_caps if c['phase']==1]
fwd_caps  = [c for c in all_caps if c['phase']==2]

print(f'\n[结果]')
print(f'  基线 WSASend: {len(base_caps)} 次')
print(f'  转发窗口 WSASend: {len(fwd_caps)} 次')

# 提取基线中 bt[0] 频率
from collections import Counter
base_bt0 = Counter(c['bt'][0] if c['bt'] else 'none' for c in base_caps)
fwd_bt0  = Counter(c['bt'][0] if c['bt'] else 'none' for c in fwd_caps)

print(f'\n  基线 bt[0] 分布:')
for rva, cnt in base_bt0.most_common(5):
    print(f'    {rva} x{cnt}')

print(f'\n  转发窗口 bt[0] 分布:')
for rva, cnt in fwd_bt0.most_common(10):
    new = '' if rva in base_bt0 else '  ★NEW'
    print(f'    {rva} x{cnt}{new}')

# 找新出现的 bt0
new_bt0s = set(fwd_bt0) - set(base_bt0)
if new_bt0s:
    print(f'\n  ★ 转发新出现的调用栈入口:')
    for rva in new_bt0s:
        matching = [c for c in fwd_caps if c['bt'] and c['bt'][0]==rva]
        print(f'\n    bt[0]={rva} x{len(matching)}')
        for c in matching[:2]:
            print(f'      buf={c["buf"]} full_bt={c["bt"]}')

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'wsasend_fwd_bt_{ts}.json'
out.write_text(json.dumps(all_caps, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

sc.unload()
sess.detach()
os._exit(0)
