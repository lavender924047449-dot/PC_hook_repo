# hook_send_frames.py
# 挂钩 WSASend 调用栈最高帧，读寄存器 + args，寻找明文 XML/消息内容
#
# 执行：
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/hook_send_frames.py

import frida, subprocess, sys, os, time, threading, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

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

// 绝对地址（从 wsasend_bt.py 的调用栈）
var FRAME_ADDRS = [0x990e58a, 0x990e75d, 0x9908363];
var FRAME_LABELS = ['f2_top', 'f1_mid', 'f0_near_ws'];

var hits = [];
var MAX = 100;

function readStr(ptr_val, max_len) {
    if (!ptr_val || ptr_val < 0x10000 || ptr_val > 0x7fffffff) return '';
    try {
        var s = ptr(ptr_val).readCString(max_len || 128);
        return s ? s : '';
    } catch(e) { return ''; }
}

function readHex(ptr_val, n) {
    if (!ptr_val || ptr_val < 0x10000 || ptr_val > 0x7fffffff) return '';
    try {
        var b = ptr(ptr_val).readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return ''; }
}

FRAME_ADDRS.forEach(function(addr, idx) {
    try {
        Interceptor.attach(ptr(addr), {
            onEnter: function(args) {
                if (hits.length >= MAX) return;
                var ctx = this.context;
                var entry = {
                    label: FRAME_LABELS[idx],
                    ecx: ctx.ecx.toInt32(),
                    esi: ctx.esi.toInt32(),
                    edi: ctx.edi.toInt32(),
                    eax: ctx.eax.toInt32(),
                    args: []
                };
                // args[0..7] + string deref
                for (var j = 0; j < 6; j++) {
                    try {
                        var av = args[j].toInt32();
                        var s = readStr(av, 128);
                        var h = '';
                        if (!s) h = readHex(av, 32);
                        entry.args.push({val: av, str: s, hex: h});
                    } catch(e) {
                        entry.args.push({val: 0, str: '', hex: ''});
                    }
                }
                // 读 ECX 处 64 字节
                entry.ecx_data = readHex(ctx.ecx.toInt32(), 64);
                // 读 ESI 处 64 字节
                entry.esi_data = readHex(ctx.esi.toInt32(), 64);
                hits.push(entry);
            }
        });
        send({t:'attached', label: FRAME_LABELS[idx], addr: '0x'+addr.toString(16)});
    } catch(e) {
        send({t:'err', label: FRAME_LABELS[idx], msg: e.message});
    }
});

recv('dump', function(_) {
    send({t:'dump_result', hits: hits});
});

send({t:'ready'});
"""

all_hits = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        desc = msg.get('description', '')[:200]
        print(f'[Frida ERR] {desc}', flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t', '')
    if t in ('attached', 'err', 'ready'):
        print(f'  [{t}] {p}', flush=True)
    elif t == 'progress':
        print(f'  hits={p.get("n")}', flush=True)
    elif t == 'dump_result':
        all_hits.extend(p.get('hits', []))
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print('\n=== 请在 30 秒内转发消息 ===', flush=True)
print('右键消息 → 转发 → 选联系人 → 发送', flush=True)
time.sleep(30)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

print(f'\n[+] 总命中: {len(all_hits)}', flush=True)

# 分析
seen_labels = set()
for h in all_hits:
    lbl = h.get('label', '')
    if lbl not in seen_labels:
        seen_labels.add(lbl)
        print(f'\n--- {lbl} @ {h} ---', flush=True)

for h in all_hits[:30]:
    print(f'\n[{h["label"]}]', flush=True)
    print(f'  ECX=0x{h["ecx"]:08x} ESI=0x{h["esi"]:08x} EDI=0x{h["edi"]:08x}', flush=True)
    for i, a in enumerate(h.get('args', [])):
        s = a.get('str', '')
        hx = a.get('hex', '')
        if s or hx:
            print(f'  arg[{i}]=0x{a["val"]:08x}  str={s[:60]!r}  hex={hx[:40]}', flush=True)
    ecx_data = h.get('ecx_data', '')
    esi_data = h.get('esi_data', '')
    if ecx_data:
        try:
            bs = bytes.fromhex(ecx_data.replace(' ', ''))
            readable = ''.join(c for c in bs.decode('utf-8', errors='ignore') if c.isprintable())
            if readable:
                print(f'  ECX deref: {readable[:80]!r}', flush=True)
        except:
            pass
    if esi_data:
        try:
            bs = bytes.fromhex(esi_data.replace(' ', ''))
            readable = ''.join(c for c in bs.decode('utf-8', errors='ignore') if c.isprintable())
            if readable:
                print(f'  ESI deref: {readable[:80]!r}', flush=True)
        except:
            pass

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'hook_frames_{ts}.json'
out.write_text(json.dumps(all_hits, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}', flush=True)

os._exit(0)
