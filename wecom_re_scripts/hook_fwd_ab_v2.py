# hook_fwd_ab_v2.py — 新版布局 A/B 差分（magic@+56, handler@+60）
# Round A: 转发到 FTA；Round B: 转发到外部联系人
# 两 sentinel 触发：_fwd_a.flag 切到 Round B；_fwd_b.flag 结束 dump
import frida, subprocess, sys, os, time, json
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
SA = OUT / '_fwd_a.flag'
SB = OUT / '_fwd_b.flag'
for f in (SA, SB):
    if f.exists(): f.unlink()

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('WXWork :9882 not found')

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;

function safeR(p, n) {
    try { return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e) { return null; }
}

// 新版：meta+56 找 magic d0070002，magic+4 (即 meta+60) 是 handler ptr
function parseMeta(beginV) {
    var out = { metaPtr: 0, magicOff: -1, handlerPtr: 0 };
    try {
        var task = new Uint8Array(ptr(beginV).readByteArray(112));
        var mp = (task[52])|(task[53]<<8)|(task[54]<<16)|(task[55]<<24);
        mp = mp >>> 0;
        out.metaPtr = mp;
        if (mp > 0x10000000) {
            var m = new Uint8Array(ptr(mp).readByteArray(256));
            for (var i = 0; i < m.length - 7; i++) {
                if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                    out.magicOff = i;
                    out.handlerPtr = (m[i+4] | (m[i+5]<<8) | (m[i+6]<<16) | (m[i+7]<<24)) >>> 0;
                    break;
                }
            }
        }
    } catch(e) {}
    return out;
}

// phase: 1=baseline, 2=round A (转 FTA), 3=round B (转外部)
var phase = 1;
// key = handler_ptr（新版本 magic@+56 后的指针）
var baselineHandlers = {};
var events = [];  // 全量事件（含 phase 标签）

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var info = parseMeta(beginV);
        var hkey = '0x' + info.handlerPtr.toString(16);

        if (phase === 1) {
            baselineHandlers[hkey] = (baselineHandlers[hkey] || 0) + 1;
            return;
        }
        var isNew = !baselineHandlers[hkey];
        if (!isNew) return;  // 只记录 Phase1 未见过的 handler

        // dump 完整 task + meta
        var task = safeR(beginV, 112);
        var meta = info.metaPtr ? safeR(info.metaPtr, 512) : null;
        events.push({
            phase: phase,
            ts: Date.now(),
            begin: '0x' + beginV.toString(16),
            metaPtr: '0x' + info.metaPtr.toString(16),
            magicOff: info.magicOff,
            handlerPtr: hkey,
            task: task,
            meta: meta,
        });
        send({t:'ev', phase: phase, handler: hkey, n: events.length});
    }
});

// 也 hook 0x449fa7 试试新版是否触发
var c449 = 0;
var args449 = [];
Interceptor.attach(base.add(0x449fa7), {
    onEnter: function(args) {
        c449++;
        if (phase < 2) return;
        try {
            var a1 = args[1];
            var a1v = a1.toInt32() >>> 0;
            if (a1v < 0x10000) return;
            var buf = Array.from(new Uint8Array(a1.readByteArray(256)));
            args449.push({phase: phase, ts: Date.now(), a1: '0x'+a1v.toString(16), buf: buf});
            if (args449.length > 60) args449.shift();
        } catch(e) {}
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go', phase: 2}); });
recv('phase3', function(_) { phase = 3; send({t:'go', phase: 3}); });
recv('dump', function(_) {
    send({t:'dump',
          events: events,
          args449: args449,
          c449: c449,
          baselineHandlers: baselineHandlers});
});
send({t:'ready', base: base.toString()});
"""

events, args449, dump_ok = [], [], [False]
baseline_handlers = {}
c449_total = 0

def on_msg(msg, data):
    global c449_total
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:250]}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    if p.get('t') == 'ready':
        print(f'[+] ready wxBase={p["base"]}')
    elif p.get('t') == 'go':
        ph = p.get('phase')
        role = 'A(→FTA)' if ph == 2 else 'B(→外部)'
        print('\n' + '='*60)
        print(f'>>> Phase {ph} ({role}) 已激活，请转发 <<<')
        print('='*60 + '\n')
    elif p.get('t') == 'ev':
        print(f'  ★ Phase{p["phase"]} #{p["n"]} handler={p["handler"]}')
    elif p.get('t') == 'dump':
        events.extend(p.get('events', []))
        args449.extend(p.get('args449', []))
        baseline_handlers.update(p.get('baselineHandlers', {}))
        c449_total = p.get('c449', 0)
        dump_ok[0] = True

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)
print('[Phase1] 8s baseline...')
time.sleep(8)
print(f'  baseline 期收集到 {"?"}  handler pool')

# Round A
sc.post({'type': 'phase2'})
print(f'\n[等 Round A sentinel] 请转发 1 次到 FTA，然后创建 {SA.name}')
t0 = time.time()
while not SA.exists() and time.time() - t0 < 15*60:
    time.sleep(0.5)
if SA.exists():
    try: SA.unlink()
    except: pass
    print(f'  [+] Round A 完成 ({time.time()-t0:.1f}s)')
time.sleep(2)

# Round B
sc.post({'type': 'phase3'})
print(f'\n[等 Round B sentinel] 请转发 1 次到外部联系人（非 FTA），然后创建 {SB.name}')
t0 = time.time()
while not SB.exists() and time.time() - t0 < 15*60:
    time.sleep(0.5)
if SB.exists():
    try: SB.unlink()
    except: pass
    print(f'  [+] Round B 完成 ({time.time()-t0:.1f}s)')
time.sleep(2)

sc.post({'type': 'dump'})
t0 = time.time()
while not dump_ok[0] and time.time() - t0 < 5:
    time.sleep(0.2)

# 分析
by_phase = {2: [], 3: []}
for e in events:
    by_phase.setdefault(e['phase'], []).append(e)
handlers_A = set(e['handlerPtr'] for e in by_phase.get(2, []))
handlers_B = set(e['handlerPtr'] for e in by_phase.get(3, []))
only_A = handlers_A - handlers_B
only_B = handlers_B - handlers_A
both = handlers_A & handlers_B

print(f'\n[结果]')
print(f'  baseline pool: {len(baseline_handlers)}')
print(f'  Round A NEW events: {len(by_phase.get(2,[]))}  distinct handlers: {len(handlers_A)}')
print(f'  Round B NEW events: {len(by_phase.get(3,[]))}  distinct handlers: {len(handlers_B)}')
print(f'  A only: {only_A}')
print(f'  B only: {only_B}')
print(f'  A∩B   : {both}')
print(f'  0x449fa7 total: {c449_total}, args samples: {len(args449)}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'fwd_ab_v2_{ts}.json'
out.write_text(json.dumps({
    'pid': pid, 'ts': ts,
    'events': events,
    'args449': args449,
    'c449': c449_total,
    'baselineHandlers': baseline_handlers,
    'summary': {
        'only_A': list(only_A),
        'only_B': list(only_B),
        'both': list(both),
    }
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] {out}')
sc.unload()
sess.detach()
os._exit(0)
