# wsasend_bt.py
# 挂 WSASend_wrap (RVA 0x4493C0) + ws2_32!WSASend，
# 捕获调用栈 + 前 2KB 数据，对比转发 vs 基线
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/wsasend_bt.py

import frida, subprocess, time, json, sys, os, threading, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
COLLECT_SEC = 60

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID = {pid}', flush=True)

JS = r"""
'use strict';

var wxBase = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
}).base;

// WSASend_wrap in WXWork (RVA 0x4493C0)
var wrapAddr = wxBase.add(0x4493C0);

// 也挂 ws2_32.dll 的 WSASend（系统级）
var ws2 = Process.getModuleByName('ws2_32.dll');
var wsaSendExport = ws2.enumerateExports().find(function(e){
    return e.name === 'WSASend' && e.type === 'function';
});

var sends = [];      // baseline sends
var fwdSends = [];   // forward sends
var phase = 'idle';  // idle / baseline / forward
var fwdHit = 0;
var baseHit = 0;

function captureSend(args, src) {
    try {
        var buf = args[1];        // LPWSABUF buffers array
        var bufCnt = args[2].toInt32(); // dwBufferCount
        var data = '';
        var totalLen = 0;
        for (var i=0; i<Math.min(bufCnt, 4); i++) {
            var pLen = buf.add(i * 8).readU32();
            var pBuf = buf.add(i * 8 + 4).readPointer();
            totalLen += pLen;
            var n = Math.min(pLen, 512);
            try {
                var raw = pBuf.readByteArray(n);
                data += Array.from(new Uint8Array(raw)).map(function(x){
                    return ('0'+x.toString(16)).slice(-2);
                }).join(' ') + '|';
            } catch(e) {}
        }
        // backtrace 4 frames
        var bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,6).map(function(a){
            return DebugSymbol.fromAddress(a).toString();
        });
        return {
            ts: Date.now(),
            src: src,
            totalLen: totalLen,
            data: data,
            bt: bt
        };
    } catch(e) { return null; }
}

var wrapHook = null, sysHook = null;

function attach() {
    // 系统 WSASend
    if (wsaSendExport) {
        sysHook = Interceptor.attach(wsaSendExport.address, {
            onEnter: function(args) {
                if (phase === 'idle') return;
                var rec = captureSend.call(this, args, 'sys');
                if (!rec) return;
                if (phase === 'baseline') { baseHit++; if (baseHit <= 200) sends.push(rec); }
                if (phase === 'forward')  { fwdHit++;  if (fwdHit <= 200) fwdSends.push(rec); }
                if ((baseHit + fwdHit) % 10 === 0)
                    send({t:'progress', phase:phase, base:baseHit, fwd:fwdHit});
            }
        });
    }
    send({t:'ready',
        wrap: wrapAddr.toString(),
        sys: wsaSendExport ? wsaSendExport.address.toString() : 'none'
    });
}

attach();

recv('start_baseline', function(_) { phase = 'baseline'; send({t:'ack', msg:'baseline started'}); });
recv('start_forward',  function(_) { phase = 'forward';  send({t:'ack', msg:'forward started'}); });
recv('dump', function(_) {
    phase = 'idle';
    send({t:'dump_result', baseline: sends, forward: fwdSends,
          baseHit: baseHit, fwdHit: fwdHit});
});
"""

baseline_data = []
forward_data = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[Frida ERR] {msg.get("description","")[:300]}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print(f'[+] Hook READY  wrap={p.get("wrap")}  sys={p.get("sys")}', flush=True)
    elif t == 'ack':
        print(f'[*] {p.get("msg")}', flush=True)
    elif t == 'progress':
        print(f'  [{p.get("phase")}] base={p.get("base")} fwd={p.get("fwd")}', flush=True)
    elif t == 'dump_result':
        baseline_data.extend(p.get('baseline', []))
        forward_data.extend(p.get('forward', []))
        print(f'[+] Dump: baseline={p.get("baseHit")} fwd={p.get("fwdHit")}', flush=True)
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

# Phase 1: baseline
print(f'\n[Phase 1] Baseline ({COLLECT_SEC}s) - 请正常使用企微（不要转发）', flush=True)
sc.post({'type': 'start_baseline'})
time.sleep(COLLECT_SEC)

# Phase 2: forward
print(f'\n{"="*60}', flush=True)
print(f'★★★ [Phase 2] 请立即转发消息！({COLLECT_SEC}s) ★★★', flush=True)
print(f'  右键消息 → 转发 → 选联系人 → 发送（可多次）', flush=True)
print(f'{"="*60}\n', flush=True)
sc.post({'type': 'start_forward'})
time.sleep(COLLECT_SEC)

print('[*] Dumping...', flush=True)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── diff 分析 ────────────────────────────────────────────────────────────────

def first_bytes(hexdata, n=8):
    """取前 n 字节作为 signature"""
    parts = hexdata.split('|')[0].split()
    return ' '.join(parts[:n])

base_sigs = set(first_bytes(r['data']) for r in baseline_data if r['data'])
fwd_sigs  = set(first_bytes(r['data']) for r in forward_data if r['data'])
new_sigs  = fwd_sigs - base_sigs

print(f'\n{"="*60}', flush=True)
print(f'[=== WSASend 分析 ===]', flush=True)
print(f'  baseline sends: {len(baseline_data)}  (unique signatures: {len(base_sigs)})', flush=True)
print(f'  forward  sends: {len(forward_data)}  (unique signatures: {len(fwd_sigs)})', flush=True)
print(f'  forward-only signatures: {len(new_sigs)}', flush=True)

print(f'\n  【转发专属调用（前5条）】', flush=True)
shown = 0
for rec in forward_data:
    if not rec['data']: continue
    sig = first_bytes(rec['data'])
    if sig in new_sigs:
        shown += 1
        if shown > 5: break
        print(f'  --- send #{shown} totalLen={rec["totalLen"]} ---', flush=True)
        # 显示前 64 字节
        parts = rec['data'].split('|')[0].split()
        print(f'    data[0:64]: {" ".join(parts[:64])}', flush=True)
        # 调用栈
        for f in rec.get('bt', []):
            print(f'    BT: {f}', flush=True)
        print(flush=True)

# 保存
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'wsasend_bt_{ts_str}.json'
out_path.write_text(json.dumps({
    'baseline': baseline_data,
    'forward': forward_data
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] 保存: {out_path}', flush=True)

os._exit(0)
