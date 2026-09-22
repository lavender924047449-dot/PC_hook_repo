# find_presend2.py — 用严格 prologue 探测器重新钉 PreSendNewMessage
# 关键：真函数入口前 1B 必是 CC (INT3 padding) 或 C3 (ret) 或 C2 XX XX (retn)

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')

TARGETS = [
    "PreSendNewMessage",
    "PreSendMessageTask2",
    "SerializeToString",
    # 也试新的关键词
    "PreSendMessageTask",
    "SendMessageTask2",
    "SendCGIRequest",
    "cgi request:",
    "before compress",
]

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');

function findSections() {
    var pe = mod.base;
    var ntOff = pe.add(0x3c).readU32();
    var nt = pe.add(ntOff);
    var numSec = nt.add(4 + 2).readU16();
    var sizeOfOpt = nt.add(4 + 16).readU16();
    var secHdr = nt.add(4 + 20 + sizeOfOpt);
    var sections = {};
    for (var i=0; i<numSec; i++) {
        var h = secHdr.add(i*40);
        var nb = new Uint8Array(h.readByteArray(8));
        var name = '';
        for (var b=0; b<8 && nb[b]!==0; b++) name += String.fromCharCode(nb[b]);
        sections[name] = {base: mod.base.add(h.add(12).readU32()), size: h.add(8).readU32()};
    }
    return sections;
}
var secs = findSections();

function strHex(s) {
    var out = '';
    for (var i=0; i<s.length; i++) out += ('0'+s.charCodeAt(i).toString(16)).slice(-2) + ' ';
    return out.trim();
}
function dwordHex(v) {
    return ('0'+(v&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>8)&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>16)&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>24)&0xff).toString(16)).slice(-2);
}

// 严格 prologue: 前 1B 是 CC / C3 / (C2 XX XX 前 3B)，且当前 3B 是 55 8B EC
// 或 sub esp 变体: 55 8B EC 83 EC ??
function findPrologueStrict(addr, maxBack) {
    var back = maxBack || 0x800;
    for (var i = 4; i < back; i++) {
        try {
            var p = addr.sub(i);
            var b0 = p.readU8(), b1 = p.add(1).readU8(), b2 = p.add(2).readU8();
            if (!(b0 === 0x55 && b1 === 0x8b && b2 === 0xec)) continue;
            // 检查前 1B
            var prev = p.sub(1).readU8();
            if (prev === 0xcc || prev === 0xc3) return {addr: p, distance: i, boundary: prev};
            // 检查 retn 0x?? (C2 XX XX) — prev3 = C2
            if (i >= 3) {
                var prev3 = p.sub(3).readU8();
                if (prev3 === 0xc2) return {addr: p, distance: i, boundary: 0xc2};
            }
            // 或前 4B 都是 CC (常见 padding)
            var pm = p.sub(4).readU8();
            if (prev === 0xcc || pm === 0xcc) return {addr: p, distance: i, boundary: 0xcc};
        } catch(e) { break; }
    }
    return null;
}

var targets = %TARGETS%;

for (var ti=0; ti<targets.length; ti++) {
    var s = targets[ti];
    var pat = strHex(s);
    var strHits = [];
    try { strHits = Memory.scanSync(secs['.rdata'].base, secs['.rdata'].size, pat); } catch(e){ continue; }

    if (strHits.length === 0) {
        send({t:'str', s:s, count:0, results:[]}); continue;
    }

    var out = [];
    for (var sh=0; sh<strHits.length && sh<5; sh++) {
        var sAddr = strHits[sh].address;
        var refHits = [];
        try { refHits = Memory.scanSync(secs['.text'].base, secs['.text'].size, dwordHex(sAddr.toUInt32())); } catch(e){}

        var funcs = [];
        for (var rh=0; rh<refHits.length && rh<8; rh++) {
            var xa = refHits[rh].address;
            var pro = findPrologueStrict(xa, 0x800);
            var f = {xref: xa.toString(), xref_rva:'0x'+xa.sub(mod.base).toString(16)};
            if (pro) {
                f.func = pro.addr.toString();
                f.func_rva = '0x'+pro.addr.sub(mod.base).toString(16);
                f.distance = pro.distance;
                f.boundary = '0x'+pro.boundary.toString(16);
            }
            funcs.push(f);
        }
        out.push({s_addr: sAddr.toString(), s_rva: '0x'+sAddr.sub(mod.base).toString(16), xref_count: refHits.length, funcs: funcs});
    }
    send({t:'str', s:s, count: strHits.length, results: out});
}
send({t:'done'});
"""
JS = JS.replace('%TARGETS%', json.dumps(TARGETS))

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

results = []; done = {'v': False}
def on_msg(msg, data):
    if msg.get('type')=='error': print(f'[ERR] {msg.get("description","")[:200]}',flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t')
    if t == 'done': done['v']=True; return
    if t != 'str': return
    results.append(p)
    if p['count']==0: print(f'\n[-] {p["s"]!r} NOT FOUND',flush=True); return
    print(f'\n[+] {p["s"]!r} × {p["count"]}',flush=True)
    for r in p['results']:
        print(f'    str @ {r["s_addr"]} RVA={r["s_rva"]}  xref={r["xref_count"]}',flush=True)
        for f in r['funcs']:
            if 'func_rva' in f:
                print(f'        xref @ {f["xref"]} → 函数 ★ RVA={f["func_rva"]}  (back {f["distance"]}B, boundary={f["boundary"]})',flush=True)
            else:
                print(f'        xref @ {f["xref"]} (no strict prologue)',flush=True)

pid = get_pid(); print(f'[*] PID={pid}, attaching...',flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS); sc.on('message', on_msg); sc.load()
import time
for _ in range(60):
    if done['v']: break
    time.sleep(1)
sc.unload(); sess.detach()

out_p = OUT_DIR / f'find_presend2_{ts}.json'
out_p.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')

# 汇总（严格边界找到的）
print(f'\n{"="*72}\n★ 汇总（严格边界找到的函数入口 RVA）:',flush=True)
for r in results:
    all_funcs = []
    for x in r.get('results', []):
        for f in x.get('funcs', []):
            if 'func_rva' in f:
                all_funcs.append((f['func_rva'], f['distance'], f['boundary']))
    if all_funcs:
        uniq = {}
        for rv, d, b in all_funcs:
            if rv not in uniq or d < uniq[rv][0]: uniq[rv] = (d, b)
        for rv, (d, b) in sorted(uniq.items()):
            print(f'  {r["s"]!r:35s} → {rv}  (back {d}B, boundary={b})',flush=True)

print(f'[+] → {out_p.name}',flush=True)
os._exit(0)
