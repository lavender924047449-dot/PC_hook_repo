# all_compact_diff.py
# 挂 CGI_A(0x390B39) + CGI_B(0x430B39)
# 第一阶段(10s)记录基线，然后让用户转发，第二阶段(10s)记录新出现的compact
import frida, subprocess, sys, os, time, threading, json
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
send({t:'base', v:wxBase.toString()});

var records = [];
var phase = 0; // 0=warmup,1=baseline,2=forward

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

function hook(rva, name) {
    try {
        Interceptor.attach(wxBase.add(rva), {
            onEnter: function(args) {
                if (phase === 0) return;
                var compact = '';
                try {
                    var b = new Uint8Array(args[1].readByteArray(4));
                    compact = ('0'+b[0].toString(16)).slice(-2)+('0'+b[1].toString(16)).slice(-2)
                            + ('0'+b[2].toString(16)).slice(-2)+('0'+b[3].toString(16)).slice(-2);
                } catch(e) { compact = '????????'; }
                var a3v = 0;
                try { a3v = args[3].toInt32()>>>0; } catch(e){}
                var now = Date.now();
                records.push({phase:phase, fn:name, compact:compact, a3:'0x'+(a3v).toString(16), ts:now});
            }
        });
        send({t:'ok', fn:name});
    } catch(e) { send({t:'fail', fn:name, m:e.message}); }
}

hook(0x390B39, 'CGI_A');
hook(0x430B39, 'CGI_B');

recv('setphase', function(v) { phase = v.phase; send({t:'ack_phase', phase:phase}); });
recv('dump', function(_) { send({t:'dump', records:records}); });
send({t:'ready'});
"""

records = []
phase_lock = threading.Lock()
dump_event = threading.Event()

def on_msg(msg, data):
    if msg.get('type') == 'error': print(f'ERR: {msg.get("description","")}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'base': print(f'  wxBase={p["v"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'ready': print('[+] Hooks ready')
    elif t == 'dump':
        records.extend(p['records'])
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1.5)

# === Phase 1: Baseline (10s) ===
print('\n[Phase 1] 10s 基线记录中...')
sc.post({'type':'setphase', 'phase':1})
time.sleep(10)

# 读取基线 compacts
sc.post({'type':'dump'})
dump_event.wait(5)
baseline = set(r['compact'] for r in records if r['phase']==1)
baseline_cnt = {c:0 for c in baseline}
for r in records:
    if r['phase']==1: baseline_cnt[r['compact']] = baseline_cnt.get(r['compact'],0)+1
print(f'  基线 compact ({len(baseline)}个): {sorted(baseline)}')

records.clear()
dump_event.clear()

# === Phase 2: 等待转发 ===
print('\n' + '='*60)
print('*** 请立即在企微中转发一条消息（图片/文字均可）***')
print('='*60)
sc.post({'type':'setphase', 'phase':2})
time.sleep(15)

sc.post({'type':'dump'})
dump_event.wait(5)

fwd_compacts = {}
for r in records:
    if r['phase']==2:
        c = r['compact']
        fwd_compacts[c] = fwd_compacts.get(c, 0) + 1

print(f'\n[Phase 2] 15s 内观察到 {len(records)} 次 CGI 调用')
new_ones = {c:n for c,n in fwd_compacts.items() if c not in baseline}
also_baseline = {c:n for c,n in fwd_compacts.items() if c in baseline}

print(f'\n  ★ 新出现（非基线）compact ({len(new_ones)}个):')
for c, n in sorted(new_ones.items()):
    fn = next((r['fn'] for r in records if r['compact']==c), '?')
    print(f'    {c} x{n} ({fn})')

print(f'\n  常规（基线已有）compact ({len(also_baseline)}个):')
for c, n in sorted(also_baseline.items()):
    print(f'    {c} x{n}')

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'all_compact_diff_{ts}.json'
out.write_text(json.dumps({'baseline':list(baseline), 'records':records}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

sc.unload()
sess.detach()
os._exit(0)
