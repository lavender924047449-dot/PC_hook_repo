# probe_a1_now.py — 即时读取稳定 args[1]=0x25df0068，并 hook 等待下一次 HIT
import frida, subprocess, sys, os, time, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
A1_ADDR = 0x25df0068  # 两次 HIT 均相同

def get_pid():
    o = subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

JS = r"""
'use strict';
var A1 = """ + hex(A1_ADDR) + """;
var hookPtr = Process.getModuleByName('WXWork.exe').base.add(0x963E58A);

function u32(a,i){ return ((a[i]|(a[i+1]<<8)|(a[i+2]<<16)|(a[i+3]<<24))>>>0); }
function toHex(ab){ var a=new Uint8Array(ab),s=''; for(var i=0;i<a.length;i++) s+=('0'+a[i].toString(16)).slice(-2); return s; }
function isHeap(v){ return v>0x00400000 && v<0x7F000000; }

// 即时 dump args[1]
var a1raw = ptr(A1).readByteArray(8192);
send({t:'a1_dump', hex: toHex(a1raw)});

// 找所有 size 字段（任意 N 在 100~5000）
var a = new Uint8Array(a1raw);
var sizes = [];
for (var i=0; i+3<a.length; i+=4) {
    var sz = u32(a,i);
    if (sz >= 100 && sz <= 5000) {
        var pv = (i>=16) ? u32(a,i-16) : 0;
        var pv2 = (i>=4) ? u32(a,i-4) : 0;
        if (isHeap(pv)) sizes.push({off:i, size:sz, ptr:pv, layout:'str16'});
        if (isHeap(pv2)) sizes.push({off:i, size:sz, ptr:pv2, layout:'adj'});
    }
}
send({t:'a1_sizes', hits: sizes.slice(0, 30)});

// hook 等下一次
Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        var a2v = args[2].toUInt32();
        try {
            var a2s = ptr(a2v).readCString(512) || '';
        } catch(e) { return; }
        if (a2s.indexOf('cgi request:1001') < 0 || a2s.indexOf('before compress') < 0) return;
        var m = a2s.match(/before compress length (\d+)/);
        if (!m) return;
        var N = parseInt(m[1]);

        // 命中时 dump args[1] + 按 N 找 buffer
        var raw = ptr(A1).readByteArray(8192);
        var ba = new Uint8Array(raw);
        var cands = [];
        for (var i=0; i+3<ba.length; i+=4) {
            if (u32(ba,i) !== N) continue;
            if (i>=16 && isHeap(u32(ba,i-16))) cands.push({p:u32(ba,i-16), src:'a1_str16_off'+i});
            if (i>=4 && isHeap(u32(ba,i-4))) cands.push({p:u32(ba,i-4), src:'a1_adj_off'+i});
        }
        // 也 dump args[1] 头部
        send({t:'hit', N:N, a1_hex: toHex(raw).slice(0,512),
              args: ['0x'+args[0].toUInt32().toString(16),
                     '0x'+args[1].toUInt32().toString(16),
                     '0x'+args[2].toUInt32().toString(16),
                     '0x'+args[3].toUInt32().toString(16),
                     '0x'+args[4].toUInt32().toString(16)],
              cands: cands});
        for (var ci=0; ci<cands.length; ci++) {
            try {
                var pb = ptr(cands[ci].p).readByteArray(N);
                send({t:'proto', src:cands[ci].src, addr:'0x'+cands[ci].p.toString(16),
                      hex: toHex(pb), N:N});
            } catch(e) {}
        }
    }
});
send({t:'ready'});
"""

pid = get_pid()
print(f'[+] PID={pid}  读取 args[1]=0x{A1_ADDR:x}', flush=True)

hits = []
def on_msg(msg, data):
    if msg.get('type')=='error':
        print('[ERR]', msg.get('description','')[:300], flush=True); return
    if msg.get('type')!='send': return
    p = msg['payload']; t = p.get('t','')
    if t=='ready':
        print('[+] hook ready，请再发一条消息…', flush=True)
    elif t=='a1_dump':
        raw = bytes.fromhex(p['hex'])
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = OUT_DIR / f'a1_snapshot_{ts}.bin'
        path.write_bytes(raw)
        print(f'[+] args[1] 快照 8192B → {path.name}', flush=True)
    elif t=='a1_sizes':
        print(f'[+] args[1] 内 size 字段候选 {len(p["hits"])} 个:', flush=True)
        for h in p['hits'][:15]:
            print(f'    off=0x{h["off"]:x} size={h["size"]} ptr=0x{h["ptr"]:x} ({h["layout"]})', flush=True)
    elif t=='hit':
        print(f'\n★ HIT N={p["N"]} args={p["args"]}', flush=True)
        print(f'  a1 内 size==N 候选: {len(p["cands"])}', flush=True)
        hits.append(p)
    elif t=='proto':
        raw = bytes.fromhex(p['hex'])
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fn = OUT_DIR / f'proto_hit_{ts}_{p["src"]}.bin'
        fn.write_bytes(raw)
        asc = raw[:200].decode('latin-1','replace')
        has_cid = '1688855' in asc or b'S:1688' in raw
        print(f'  [{p["src"]}] addr={p["addr"]} N={p["N"]} CID={has_cid} → {fn.name}', flush=True)
        print(f'    head={raw[:48].hex()}', flush=True)

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(90)
try: sc.unload()
except: pass
try: sess.detach()
except: pass
print(f'\n[+] 完成，HIT {len(hits)} 次', flush=True)
os._exit(0)
