# xref_tag4.py — 搜索 tag4 CGI 路由字符串及 code xref（reverse-engineering 静态+动态）
import frida, subprocess, sys, os, time, json
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

TAGS = ['WbWC', 'W1pd', '417+', 'ZSBQ', 'd0070002']

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('WXWork not found')

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
var size = wx.size;
send({t:'info', base:base.toString(), size:size});

function toPat(s) {
    return Array.from(new TextEncoder().encode(s))
        .map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ');
}

function scanStr(label, s) {
    var pat = toPat(s);
    var hits = [];
    try {
        var rs = Memory.scanSync(base, size, pat);
        rs.forEach(function(r) {
            var va = r.address;
            var rva = va.sub(base).toInt32() >>> 0;
            var ctx = '';
            try {
                var raw = new Uint8Array(va.sub(16).readByteArray(48));
                ctx = Array.from(raw).map(function(b){return ('0'+b.toString(16)).slice(-2);}).join(' ');
            } catch(e) {}
            hits.push({label:label, s:s, va:va.toString(), rva:'0x'+rva.toString(16), ctx:ctx});
        });
    } catch(e) {}
    return hits;
}

function scanBytes(label, hex4) {
    var hits = [];
    try {
        var rs = Memory.scanSync(base, size, hex4);
        rs.forEach(function(r) {
            var va = r.address;
            var rva = va.sub(base).toInt32() >>> 0;
            hits.push({label:label, s:hex4, va:va.toString(), rva:'0x'+rva.toString(16), ctx:''});
        });
    } catch(e) {}
    return hits;
}

var allHits = [];
['WbWC','W1pd','417+','ZSBQ'].forEach(function(s) {
    allHits = allHits.concat(scanStr('tag4', s));
});
allHits = allHits.concat(scanBytes('magic', 'd0 07 00 02'));

// 对每个字符串 VA，在 .text 段搜 4-byte LE 指针引用
var textBase = base;
var textSize = size;  // 全扫（慢但完整）
var xrefs = [];

allHits.forEach(function(h) {
    var va = parseInt(h.va, 16);
    var pat = [
        (va & 0xff), (va>>8)&0xff, (va>>16)&0xff, (va>>24)&0xff
    ].map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ');
    try {
        var rs = Memory.scanSync(base, size, pat);
        rs.forEach(function(r) {
            var xva = r.address;
            var xrva = xva.sub(base).toInt32() >>> 0;
            // 过滤：xref 应在代码段低地址或 rdata 范围
            xrefs.push({
                str: h.s, str_va: h.va, str_rva: h.rva,
                xref_va: xva.toString(), xref_rva: '0x'+xrva.toString(16)
            });
        });
    } catch(e) {}
});

send({t:'result', hits: allHits, xrefs: xrefs});
"""

result = {'hits': [], 'xrefs': []}

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:300]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'info':
        print(f"  base={p['base']} size={p['size']//1024//1024}MB")
    elif p.get('t') == 'result':
        result.update(p)

print('[*] Attach + scan (may take 1-3 min)...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(120)
try:
    sc.unload()
    sess.detach()
except Exception:
    pass

print(f'\n[字符串命中] {len(result["hits"])}')
for h in result['hits']:
    print(f"  {h['s']!r} VA={h['va']} RVA={h['rva']}")

print(f'\n[XREF 命中] {len(result["xrefs"])}')
for x in result['xrefs'][:30]:
    print(f"  str={x['str']!r} str_rva={x['str_rva']} <- xref_rva={x['xref_rva']}")

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'xref_tag4_{ts}.json'
out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')
os._exit(0)
