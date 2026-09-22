# cgi_proto_dump.py — hook CGI builder (RVA 0x99235A0)，逐条落盘 proto 候选
import frida, subprocess, sys, os, time, json, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
RVA_CGI_BLDPRE = 0x99235A0
CAPTURE_SEC = 45

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('WXWork 未运行')

pid = get_pid()
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'cgi_proto_{ts}.ndjson'
print(f'[+] PID={pid}  out={out.name}', flush=True)

JS = r"""
'use strict';
var hook = Process.getModuleByName('WXWork.exe').base.add(0x99235A0);
var n = 0, MAX = 20;

function readHex(p, sz) {
    try {
        return Array.from(new Uint8Array(ptr(p).readByteArray(sz))).map(function(b){
            return ('0'+b.toString(16)).slice(-2);
        }).join('');
    } catch(e) { return ''; }
}

Interceptor.attach(hook, {
    onEnter: function(args) {
        if (n >= MAX) return;
        var rec = {ts: Date.now(), args: [], blobs: []};
        for (var j=0; j<8; j++) {
            try {
                var v = args[j].toUInt32();
                rec.args.push('0x'+v.toString(16));
                if (v < 0x10000 || v > 0xffff0000) continue;
                var hx = readHex(v, 1024);
                if (!hx) continue;
                var ascii = hx.replace(/../g, function(h){
                    var b = parseInt(h,16);
                    return (b>=32&&b<127)?String.fromCharCode(b):'.';
                });
                var hasCGI = ascii.indexOf('cgi request') >= 0 || ascii.indexOf('compress length') >= 0;
                rec.blobs.push({arg:j, addr:'0x'+v.toString(16), hasCGI:hasCGI, hex1024:hx});
                // follow pointers inside first 256 bytes
                var arr = [];
                for (var k=0;k<256;k+=2) arr.push(parseInt(hx.substr(k,2),16));
                for (var i=0;i+3<256;i+=4) {
                    var pv = arr[i]|(arr[i+1]<<8)|(arr[i+2]<<16)|(arr[i+3]<<24);
                    if (pv < 0x10000 || pv > 0xffff0000) continue;
                    var ph = readHex(pv, 768);
                    if (!ph) continue;
                    var plen = ph.length/2;
                    if (plen >= 64) {
                        rec.blobs.push({arg:j, from_off:i, addr:'0x'+pv.toString(16), hex768:ph});
                    }
                }
            } catch(e) {}
        }
        n++;
        send({t:'hit', n:n, rec:rec});
    }
});
send({t:'ready', hook: hook.toString()});
"""

def on_msg(msg, _):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description','')[:200], flush=True)
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        print(f"[+] builder hook @ {p['hook']}", flush=True)
    elif p.get('t') == 'hit':
        rec = p['rec']
        with out.open('a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        cgi = any(b.get('hasCGI') for b in rec.get('blobs', []))
        print(f"  [HIT #{p['n']}] blobs={len(rec.get('blobs',[]))} CGI={cgi}", flush=True)

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
print(f'=== {CAPTURE_SEC}s 内请发文字/文件/转发 ===', flush=True)
time.sleep(CAPTURE_SEC)
sc.unload(); sess.detach()
print(f'[+] done -> {out}', flush=True)
os._exit(0)
