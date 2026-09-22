# hook_fwd_signal.py — 信号驱动版：Phase2 等待 sentinel 文件而非固定时间窗
# 用户完成转发后，创建 sentinel 文件即触发 dump
import frida, subprocess, sys, os, time, json
from datetime import datetime
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
SENTINEL = OUT / '_fwd_done.flag'
if SENTINEL.exists():
    SENTINEL.unlink()

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
function readTag4(beginV) {
    var out = { tag4: null, metaPtr: 0, magicOff: -1 };
    try {
        var task = new Uint8Array(ptr(beginV).readByteArray(112));
        var metaPtr = (task[52])|(task[53]<<8)|(task[54]<<16)|(task[55]<<24);
        metaPtr = metaPtr >>> 0;
        out.metaPtr = metaPtr;
        if (metaPtr > 0x10000000) {
            var m = new Uint8Array(ptr(metaPtr).readByteArray(512));
            for (var i = 0; i < m.length - 3; i++) {
                if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                    out.magicOff = i;
                    if (i + 28 <= m.length) {
                        out.tag4 = String.fromCharCode(m[i+24], m[i+25], m[i+26], m[i+27]);
                    }
                    break;
                }
            }
        }
    } catch(e) {}
    return out;
}

var phase = 1;
var baselineBegins = {};
var tagCounts = {};
var captures = [];
var c449 = 0;
var last449Args = [];
var FWD_TAGS = ['WbWC','b0jW','i+Ax','W1pd','417+','QzlK','ODZc'];

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        var beginV = args[1].toInt32() >>> 0;
        var endV = args[2].toInt32() >>> 0;
        var bk = '0x' + beginV.toString(16);
        var info = readTag4(beginV);
        var tag = info.tag4 || '(no-tag)';
        tagCounts[tag] = (tagCounts[tag] || 0) + 1;

        if (phase === 1) { baselineBegins[bk] = 1; return; }
        var isNewBegin = !baselineBegins[bk];
        var isFwdTag = false;
        if (info.tag4) {
            for (var fi = 0; fi < FWD_TAGS.length; fi++) {
                if (info.tag4 === FWD_TAGS[fi]) { isFwdTag = true; break; }
            }
            if (info.tag4.indexOf('+') >= 0) isFwdTag = true;
        }
        if (!isNewBegin && !isFwdTag) return;

        var sz = endV - beginV;
        var task = safeR(beginV, sz > 0 && sz <= 512 ? sz : 112);
        var meta = info.metaPtr ? safeR(info.metaPtr, 1024) : null;
        captures.push({
            ts: Date.now(), tag4: info.tag4, begin: bk,
            end: '0x' + endV.toString(16), sz: sz,
            metaPtr: '0x' + info.metaPtr.toString(16),
            magicOff: info.magicOff, task: task, meta: meta,
            phase: phase
        });
        send({t:'cap', tag: info.tag4 || '(no-tag)', begin: bk, new: isNewBegin, n: captures.length});
    }
});

// 0x449FA7 args[1] dump（含 conv 候选）
Interceptor.attach(base.add(0x449fa7), {
    onEnter: function(args) {
        c449++;
        if (phase !== 2) return;
        try {
            var a1 = args[1];
            var a1v = a1.toInt32() >>> 0;
            if (a1v < 0x10000) return;
            var buf = Array.from(new Uint8Array(a1.readByteArray(256)));
            last449Args.push({ ts: Date.now(), a1: '0x' + a1v.toString(16), buf: buf });
            if (last449Args.length > 40) last449Args.shift();
            if (c449 % 5 === 1) send({t:'449', n: c449, a1: '0x' + a1v.toString(16)});
        } catch(e) {}
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go'}); });
recv('dump', function(_) {
    send({t:'dump', captures: captures, tagCounts: tagCounts,
          c449: c449, args449: last449Args});
});
send({t:'ready', base: base.toString()});
"""

captures = []
args449 = []
tag_counts = {}
dump_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:250]}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    if p.get('t') == 'ready':
        print(f'[+] ready wxBase={p["base"]}')
    elif p.get('t') == 'go':
        print('\n' + '='*60)
        print('>>> Phase2 已激活，请现在执行 1 次转发（到 FTA）<<<')
        print(f'>>> 完成后创建 sentinel: {SENTINEL} <<<')
        print('='*60 + '\n')
    elif p.get('t') == 'cap':
        mark = 'NEW' if p['new'] else 'FWD'
        print(f'  ★ [{mark}] #{p["n"]} tag4={p["tag"]} begin={p["begin"]}')
    elif p.get('t') == '449':
        print(f'  [449FA7] 命中 #{p["n"]} a1={p["a1"]}')
    elif p.get('t') == 'dump':
        captures.extend(p.get('captures', []))
        tag_counts.update(p.get('tagCounts', {}))
        args449.extend(p.get('args449', []))
        dump_ok[0] = True
        print(f'  [dump] c449={p.get("c449",0)} captures={len(captures)} args449={len(args449)}')

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)
print('[Phase1] 6s baseline...')
time.sleep(6)
sc.post({'type': 'phase2'})

# 无限等 sentinel（最长 15 分钟兜底）
t0 = time.time()
MAX_WAIT = 15 * 60
print(f'[Phase2] 等待 sentinel 文件出现（最长 {MAX_WAIT//60} 分钟）...')
while not SENTINEL.exists():
    if time.time() - t0 > MAX_WAIT:
        print('[TIMEOUT] 未在 15min 内收到 sentinel，强制 dump')
        break
    time.sleep(0.5)
if SENTINEL.exists():
    print(f'[+] sentinel 已收到（{time.time()-t0:.1f}s 后触发 dump）')
    try: SENTINEL.unlink()
    except: pass

# 再多观察 2s 让最后事件涌入
time.sleep(2)
sc.post({'type': 'dump'})
t0 = time.time()
while not dump_ok[0] and time.time() - t0 < 5:
    time.sleep(0.2)

print(f'\n[结果] 捕获 {len(captures)} 条')
fwd = [c for c in captures if c.get('tag4') in ('WbWC','b0jW','i+Ax','W1pd','417+','QzlK','ODZc')]
print(f'  转发相关 tag4: {len(fwd)}')
for c in fwd[:20]:
    print(f'    {c.get("tag4")} begin={c.get("begin")} magicOff={c.get("magicOff")}')

print(f'\n[449FA7 args] 采样 {len(args449)} 条')

print('\n[Phase2 tag4 统计 top10]')
for t, n in Counter(tag_counts).most_common(10):
    print(f'  {repr(t)}: {n}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'fwd_signal_{ts}.json'
out.write_text(json.dumps({
    'captures': captures,
    'tagCounts': tag_counts,
    'args449': args449,
    'pid': pid,
    'ts': ts,
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] {out}')
sc.unload()
sess.detach()
os._exit(0)
