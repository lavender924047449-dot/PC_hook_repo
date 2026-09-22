# find_msgtype_enum2.py — 直接 dump 每个 msgtype 字符串周围 ±512B + xref 计数
import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')

KNOWN = {
    'text':     '0xbcb77dc',
    'voice':    '0xbd6cc98',
    'file_1':   '0xbb9eb8c',
    'file_2':   '0xbcb7c64',
    'image':    '0xbccc9c4',
    'video':    '0xbcbfedc',
    'link':     '0xbcbfee4',
    'location': '0xbd520ec',
    'card':     '0xbd696e0',
    'silk':     '0xbd69ac8',
    'amr':      '0xb79dbe0',
    'MMS':      '0xbca7650',
}

JS = """
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var targets = TARGETS_PLACEHOLDER;
var names = Object.keys(targets);

function findSections() {
    var pe = mod.base;
    var ntOff = pe.add(0x3c).readU32(); var nt = pe.add(ntOff);
    var numSec = nt.add(4 + 2).readU16(); var szOpt = nt.add(4 + 16).readU16();
    var secHdr = nt.add(4 + 20 + szOpt); var sec = {};
    for (var i=0; i<numSec; i++) {
        var h = secHdr.add(i*40);
        var nb = new Uint8Array(h.readByteArray(8)); var nm = '';
        for (var b=0; b<8 && nb[b]!==0; b++) nm += String.fromCharCode(nb[b]);
        sec[nm] = {base: mod.base.add(h.add(12).readU32()), size: h.add(8).readU32()};
    }
    return sec;
}
var secs = findSections();

function dwLE(v) {
    return ('0'+(v&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>>8)&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>>16)&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>>24)&0xff).toString(16)).slice(-2);
}

// dump 每个字符串 ±512B
for (var i=0; i<names.length; i++) {
    var nm = names[i];
    var addr = ptr(targets[nm]);
    var start = addr.sub(512);
    try {
        var raw = start.readByteArray(1024);
        var hex = '';
        var arr = new Uint8Array(raw);
        for (var j=0; j<arr.length; j++) hex += ('0'+arr[j].toString(16)).slice(-2);
        send({t:'dump', name: nm, base: start.toString(), center: addr.toString(),
              rva: '0x'+addr.sub(mod.base).toString(16), hex: hex});
    } catch(e) { send({t:'err', name: nm, e: String(e)}); }
}

// xref 计数
for (var i=0; i<names.length; i++) {
    var nm = names[i];
    var addr = ptr(targets[nm]);
    var pat = dwLE(addr.toUInt32());
    var hits = [];
    try { hits = Memory.scanSync(secs['.text'].base, secs['.text'].size, pat); } catch(e){}
    send({t:'xref', name: nm, count: hits.length, first: hits.slice(0, 5).map(function(h){return h.address.toString();})});
}

send({t:'done'});
"""
JS = JS.replace('TARGETS_PLACEHOLDER', json.dumps(KNOWN))

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

done = {'v': False}
dumps = {}; xrefs = {}
def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']; t = p.get('t')
    if t == 'done': done['v'] = True; return
    if t == 'dump':
        dumps[p['name']] = p
        raw = bytes.fromhex(p['hex'])
        # 落盘
        (OUT_DIR/f'enum_ctx_{ts}_{p["name"]}.bin').write_bytes(raw)
    elif t == 'xref':
        xrefs[p['name']] = p

pid = get_pid(); print(f'[*] PID={pid}', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS); sc.on('message', on_msg); sc.load()
import time
for _ in range(60):
    if done['v']: break
    time.sleep(1)
sc.unload(); sess.detach()

# 打印每个字符串周围的 ASCII 结构
print(f'\n{"="*74}\n[+] 每个 msgtype 字符串 ±512B ASCII 邻居（look for enum table）:\n', flush=True)

def show_neighborhood(raw, center_off):
    """在 dump 里找中心字符串前后紧邻的 ASCII run（可能是同表其他条目）"""
    # 找所有 ≥3 字符的 ASCII run
    runs = []; cur = ''; st = 0
    for i, b in enumerate(raw):
        if 0x20 <= b <= 0x7E:
            if not cur: st = i
            cur += chr(b)
        else:
            if len(cur) >= 3: runs.append((st, cur))
            cur = ''
    if len(cur) >= 3: runs.append((st, cur))
    return runs

for nm, p in dumps.items():
    raw = bytes.fromhex(p['hex'])
    # center_off = 512
    xr = xrefs.get(nm, {})
    print(f'━━━ {nm!r} @ {p["center"]} RVA={p["rva"]}  xref={xr.get("count","?")} ━━━')
    runs = show_neighborhood(raw, 512)
    for off, s in runs:
        distance = off - 512  # 距离中心（负=前面）
        marker = ' ←★中心' if abs(distance) < 3 else ''
        print(f'  {distance:+5d}B  {s[:60]!r}{marker}')
    print()

# 特别关注 xref 数多的（枚举 key 通常被引用多次）
print(f'\n{"="*74}\n[+] xref 排行:\n', flush=True)
sorted_x = sorted(xrefs.items(), key=lambda x: -x[1].get('count', 0))
for nm, x in sorted_x:
    print(f'  {nm:12s}  xref={x.get("count",0):3d}  first: {", ".join(x.get("first", [])[:3])}', flush=True)
