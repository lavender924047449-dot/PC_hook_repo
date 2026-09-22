# cgi_capture_lite.py — 轻量版 f2_top 截获，逐条落盘，避免 dump 卡死
import frida, subprocess, sys, os, time, json, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
F2_TOP_RVA = 0x963E58A
CAPTURE_SEC = 60
MAX_CAP = 30

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('未找到 :9882 LISTENING')

pid = get_pid()
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'cgi_capture_{ts_str}.ndjson'
print(f'[+] PID={pid}  out={out_path.name}', flush=True)

JS = r"""
'use strict';
var wxBase = Process.getModuleByName('WXWork.exe').base;
var hookPtr = wxBase.add(0x963E58A);
var MAX = 30;
var n = 0;

function safeRead(addr, sz) {
    try {
        var p = ptr(addr);
        if (p.toUInt32() < 0x10000) return null;
        return Array.from(new Uint8Array(p.readByteArray(sz)));
    } catch(e) { return null; }
}
function toHex(arr) {
    return arr.map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join('');
}
function ascii(arr) {
    return arr.map(function(b){ return (b>=32&&b<127)?String.fromCharCode(b):'.'; }).join('');
}
function findAscii(arr, minLen) {
    var out = [], run = '', start = 0;
    for (var i=0;i<arr.length;i++) {
        var b = arr[i];
        if (b>=32 && b<127) {
            if (!run.length) start = i;
            run += String.fromCharCode(b);
        } else {
            if (run.length >= minLen) out.push({off:start, s:run});
            run = '';
        }
    }
    if (run.length >= minLen) out.push({off:start, s:run});
    return out;
}

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (n >= MAX) return;
        var cap = {ts: Date.now(), args: [], hits: []};
        for (var ai=0; ai<5; ai++) {
            try {
                var v = args[ai].toUInt32();
                cap.args.push('0x'+v.toString(16));
                var d = safeRead(v, 1024);
                if (!d) continue;
                var strs = findAscii(d, 8);
                var joined = strs.map(function(x){return x.s;}).join('|');
                var hasURL = joined.indexOf('work.weixin.qq.com') >= 0;
                var hasCGI = joined.indexOf('cgi request') >= 0 || joined.indexOf('compress length') >= 0;
                var hasMsg = joined.indexOf('conversationId') >= 0 || joined.indexOf('ClientId') >= 0;
                if (!hasURL && !hasCGI && !hasMsg) continue;
                cap.hits.push({
                    arg: ai,
                    addr: '0x'+v.toString(16),
                    hasURL: hasURL,
                    hasCGI: hasCGI,
                    hasMsg: hasMsg,
                    strings: strs.slice(0, 12),
                    hex512: toHex(d.slice(0, 256)),
                    ascii256: ascii(d.slice(0, 256))
                });
                // follow pointers in first 512 bytes
                var ptrs = {};
                for (var pi=0; pi+3<512; pi+=4) {
                    var pv = d[pi]|(d[pi+1]<<8)|(d[pi+2]<<16)|(d[pi+3]<<24);
                    var uv = pv>>>0;
                    if (uv < 0x10000 || uv > 0xffff0000) continue;
                    var k = uv.toString(16);
                    if (ptrs[k]) continue;
                    var dd = safeRead(uv, 512);
                    if (!dd) continue;
                    var ss = findAscii(dd, 10);
                    if (ss.length) ptrs[k] = {strings: ss.slice(0,6), hex256: toHex(dd.slice(0,128))};
                }
                cap.hits[cap.hits.length-1].ptrs = ptrs;
            } catch(e) {}
        }
        if (!cap.hits.length) return;
        n++;
        send({t:'cap', n:n, cap:cap});
    }
});
send({t:'ready', hook: hookPtr.toString()});
"""

hits = []

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description','')[:200], flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print(f"[+] HOOK @ {p.get('hook')}", flush=True)
    elif p.get('t') == 'cap':
        cap = p['cap']
        hits.append(cap)
        with out_path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(cap, ensure_ascii=False) + '\n')
        notes = []
        for h in cap.get('hits', []):
            notes.append(f"arg{h['arg']} URL={h['hasURL']} CGI={h['hasCGI']}")
        print(f"  [CAP #{p['n']}] " + ', '.join(notes), flush=True)
        for h in cap.get('hits', []):
            for s in h.get('strings', [])[:4]:
                txt = s.get('s','')
                if len(txt) > 8:
                    print(f"    [{s.get('off')}] {txt[:120]!r}", flush=True)

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

print(f'\n=== 请在 {CAPTURE_SEC}s 内：发文字 / 发文件 / 转发 ===', flush=True)
time.sleep(CAPTURE_SEC)

sc.unload()
sess.detach()

print(f'\n[+] 有效捕获 {len(hits)} 条 -> {out_path}', flush=True)
os._exit(0)
