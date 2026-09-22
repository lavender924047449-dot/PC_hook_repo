# find_fwd_entry.py
# 从 RVA 0x39114b 向前搜索函数入口（PUSH EBP / MOV EBP,ESP）
# 然后 hook 该入口，捕获转发时的 compact 和 args

import frida, subprocess, sys, os, time, json, threading
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

// 从 RVA=0x39114b 向前搜索函数入口（最多搜 4KB）
var target = wxBase.add(0x39114b);
var funcEntry = null;
var funcRva = 0;

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

// 搜索模式: 55 8B EC (PUSH EBP; MOV EBP,ESP) — 标准 x86 函数入口
for (var off = 0; off < 0x1000; off++) {
    var a = target.sub(off);
    var b = safeR(a, 3);
    if (!b) continue;
    if (b[0] === 0x55 && b[1] === 0x8B && b[2] === 0xEC) {
        funcEntry = a;
        funcRva = a.sub(wxBase).toUInt32();
        send({t:'found', rva:'0x'+funcRva.toString(16), off:off});
        break;
    }
    // 也检查 53 8B DC (PUSH EBX; MOV EBX,ESP) — 另一种 prologue
    if (b[0] === 0x53 && b[1] === 0x8B && b[2] === 0xDC) {
        funcEntry = a;
        funcRva = a.sub(wxBase).toUInt32();
        send({t:'found', rva:'0x'+funcRva.toString(16), off:off, type:'53 8b dc'});
        break;
    }
}

if (!funcEntry) {
    send({t:'fail', m:'function entry not found in 4KB'});
} else {
    // 读入口处指令
    var prologueBytes = safeR(funcEntry, 32);
    send({t:'prologue', bytes: prologueBytes});

    // Hook 该函数
    try {
        Interceptor.attach(funcEntry, {
            onEnter: function(args) {
                // 读 args 并尝试解析 compact
                var argVals = [];
                for (var i = 0; i < 6; i++) {
                    try { argVals.push('0x'+(args[i].toInt32()>>>0).toString(16)); }
                    catch(e) { argVals.push('?'); }
                }
                
                // 尝试从 args[1] 读 compact（沿用之前的约定）
                var compact = '??';
                for (var ai = 0; ai < 4; ai++) {
                    try {
                        var av = args[ai].toInt32() >>> 0;
                        if (av < 0x10000) continue;
                        var b4 = new Uint8Array(ptr(av).readByteArray(4));
                        if (b4[0] === 0x01) {
                            compact = ('0'+b4[0].toString(16)).slice(-2)+('0'+b4[1].toString(16)).slice(-2)+
                                      ('0'+b4[2].toString(16)).slice(-2)+('0'+b4[3].toString(16)).slice(-2);
                        }
                    } catch(e) {}
                }
                
                var now = Date.now();
                send({t:'hit', rva:'0x'+funcRva.toString(16), args:argVals, compact:compact, ts:now});
            }
        });
        send({t:'hooked', rva:'0x'+funcRva.toString(16)});
    } catch(e) {
        send({t:'hook_fail', m:e.message});
    }
}
send({t:'ready'});
"""

ready_event = threading.Event()
hits = []

def on_msg(msg, data):
    if msg.get('type') == 'error': print(f'ERR: {msg.get("description","")}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'base': print(f'  wxBase={p["v"]}')
    elif t == 'found':
        print(f'  ★ 函数入口 RVA={p["rva"]}（从 0x39114b 回退 {p["off"]} 字节）type={p.get("type","55 8b ec")}')
    elif t == 'prologue':
        bs = bytes(p['bytes'])
        print(f'  prologue: {bs.hex()}')
    elif t == 'hooked': print(f'  [OK] Hook at {p["rva"]}')
    elif t == 'hook_fail': print(f'  [FAIL] {p["m"]}')
    elif t == 'fail': print(f'  [FAIL] {p["m"]}')
    elif t == 'ready': ready_event.set()
    elif t == 'hit':
        hits.append(p)
        print(f'  HIT rva={p["rva"]} compact={p["compact"]} args={p["args"][:4]}')

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
ready_event.wait(10)

if not ready_event.is_set():
    print('[!] Hook 超时')
    os._exit(1)

print('\n[等待] 60s 窗口 — 请在企微转发一条消息！')
print('='*60)
time.sleep(60)

print(f'\n[结果] 共 {len(hits)} 次命中')
# 统计 compact 分布
from collections import Counter
compacts = Counter(h['compact'] for h in hits)
print('compact 分布:', dict(compacts))

# 保存
from datetime import datetime
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'fwd_entry_{ts}.json'
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'[+] 保存: {out}')

sc.unload()
sess.detach()
os._exit(0)
