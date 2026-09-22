# ts_diff.py - 基于时间戳的 compact 差分捕获
# 全程 hook，Python 侧按时间切分 baseline vs forward 窗口
import frida, subprocess, sys, os, time, json
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

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

var startTs = Date.now();

function hook(rva, name) {
    try {
        Interceptor.attach(wxBase.add(rva), {
            onEnter: function(args) {
                var compact = '';
                try {
                    var b = new Uint8Array(args[1].readByteArray(4));
                    compact = ('0'+b[0].toString(16)).slice(-2)+('0'+b[1].toString(16)).slice(-2)
                            + ('0'+b[2].toString(16)).slice(-2)+('0'+b[3].toString(16)).slice(-2);
                } catch(e) { compact = '????????'; }
                // 只有非 01000000 的才实时上报（减少噪音）
                var elapsed = Date.now() - startTs;
                if (compact !== '01000000') {
                    send({t:'cgi', fn:name, compact:compact, elapsed:elapsed});
                } else {
                    // 每5秒上报一次 01000000 作为心跳
                    if (elapsed % 5000 < 200) {
                        send({t:'hb', elapsed:elapsed});
                    }
                }
            }
        });
        send({t:'ok', fn:name});
    } catch(e) { send({t:'fail', fn:name, m:e.message}); }
}

hook(0x390B39, 'CGI_A');
hook(0x430B39, 'CGI_B');
send({t:'ready'});
"""

all_events = []
start_ts = None
baseline_end_ts = None
forward_start_ts = None

def on_msg(msg, data):
    global start_ts
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'base': print(f'  wxBase={p["v"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p.get("m","")}')
    elif t == 'ready':
        start_ts = time.time()
        print('[+] HOOKS READY!')
    elif t == 'cgi':
        all_events.append(p)
        elapsed = p.get('elapsed', 0)/1000.0
        print(f'  t={elapsed:6.1f}s fn={p["fn"]} compact={p["compact"]}')
    elif t == 'hb':
        pass  # 静默心跳

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()

# 等 ready
t0 = time.time()
while start_ts is None and time.time()-t0 < 10:
    time.sleep(0.2)
if start_ts is None:
    print('[!] Hook 启动超时')
    os._exit(1)

print('\n[Phase 1] 10s 基线观察...')
time.sleep(10)
baseline_end_ts = time.time()

baseline_events = [e for e in all_events if e['elapsed'] < (baseline_end_ts - start_ts)*1000]
baseline_compacts = set(e['compact'] for e in baseline_events)
print(f'  基线 compact: {sorted(baseline_compacts)}')

print('\n' + '='*60)
print('*** 请立即在企微中转发一条消息！（图片/文字均可）***')
print('='*60)
forward_start_ts = time.time()

time.sleep(20)  # 观察 20s

# ── 分析 ──
fwd_t0_ms = (forward_start_ts - start_ts) * 1000
fwd_events = [e for e in all_events if e['elapsed'] >= fwd_t0_ms]

print(f'\n[结果] 转发窗口 20s 内 CGI 事件 ({len(fwd_events)}):')
fwd_compacts = {}
for e in fwd_events:
    c = e['compact']
    fwd_compacts[c] = fwd_compacts.get(c, 0) + 1

new_ones = {c: n for c, n in fwd_compacts.items() if c not in baseline_compacts}
print(f'\n  ★ 新出现 compact ({len(new_ones)}):')
for c, n in sorted(new_ones.items()):
    fn_list = [e['fn'] for e in fwd_events if e['compact']==c]
    print(f'    {c}  x{n}  [{fn_list[0] if fn_list else "?"}]')

print(f'\n  常规 compact ({len(fwd_compacts)-len(new_ones)}):')
for c, n in sorted(fwd_compacts.items()):
    if c in baseline_compacts:
        print(f'    {c}  x{n}')

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'ts_diff_{ts}.json'
out.write_text(json.dumps({'baseline':list(baseline_compacts), 'events':all_events}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

sc.unload()
sess.detach()
os._exit(0)
