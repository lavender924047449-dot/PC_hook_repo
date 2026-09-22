# cgi_proto_final.py — deep_a2 策略 + before-compress 过滤 + 按 N dump
# 对用户已确认的 HIT 路线：扫 args[0..7] 内所有指针 → sniff protobuf → dump N 字节
import frida, subprocess, sys, os, time, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CAPTURE_SEC = 90

JS = r"""
'use strict';
var hookPtr = Process.getModuleByName('WXWork.exe').base.add(0x963E58A);
var hits = 0;

function u32(p, off) {
    try { return p.add(off).readU32()>>>0; } catch(e) { return 0; }
}
function readN(p, n) {
    try { return p.readByteArray(n); } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s='';
    for (var i=0;i<a.length;i++) s+=('0'+a[i].toString(16)).slice(-2);
    return s;
}
function isHeap(v) { return v>0x01000000 && v<0x7F000000; }
function looksPb(ab) {
    if (!ab || ab.byteLength < 4) return false;
    var b0 = new Uint8Array(ab)[0];
    var wire = b0 & 7, field = b0 >> 3;
    return field >= 1 && field <= 200 && (wire === 0 || wire === 2);
}
function hasMark(ab) {
    if (!ab) return false;
    var a = new Uint8Array(ab);
    var s = '';
    for (var i=0; i<Math.min(a.length, 800); i++)
        s += (a[i]>=32 && a[i]<127) ? String.fromCharCode(a[i]) : '.';
    return s.indexOf('1688855')>=0 || s.indexOf('S:1688')>=0 || s.indexOf('conversation')>=0;
}
// arg2 是结构体，offset0 是 UUID C 串；readCString 会在 UUID 后 \\0 截断，必须用原始字节扫
function scanAsciiRuns(ab, minLen) {
    var a = new Uint8Array(ab), out = [], run = '';
    for (var i = 0; i < a.length; i++) {
        if (a[i] >= 0x20 && a[i] <= 0x7E) run += String.fromCharCode(a[i]);
        else { if (run.length >= minLen) out.push(run); run = ''; }
    }
    if (run.length >= minLen) out.push(run);
    return out;
}
function a2HasBeforeCompress(a2v) {
    try {
        var raw = a2v.readByteArray(4096);
        if (!raw) return {ok:false, N:0, excerpt:''};
        var joined = scanAsciiRuns(raw, 6).join('|');
        if (joined.indexOf('cgi request:1001') < 0 || joined.indexOf('before compress') < 0)
            return {ok:false, N:0, excerpt:joined.slice(0,120)};
        var m = joined.match(/before compress length (\d+)/);
        if (!m) return {ok:false, N:0, excerpt:joined.slice(0,120)};
        return {ok:true, N:parseInt(m[1]), excerpt:joined.slice(0,180)};
    } catch(e) { return {ok:false, N:0, excerpt:''}; }
}
function collectFromObj(basePtr, label, N, out, seen) {
    if (!basePtr || basePtr.isNull()) return;
    var bp = basePtr.toUInt32();
    // 直接 base 就是 buffer?
    var direct = readN(basePtr, N);
    if (direct && looksPb(direct)) {
        var k = bp.toString(16);
        if (!seen[k]) { seen[k]=1; out.push({src:label+'_direct', addr:bp, hex:toHex(direct)}); }
    }
    // 扫对象内指针 (2048B)
    for (var off=0; off<2048; off+=4) {
        var pv = u32(basePtr, off);
        if (!isHeap(pv)) continue;
        var k = pv.toString(16);
        if (seen[k]) continue;
        // 读 N 字节
        var buf = readN(ptr(pv), N);
        if (!buf) continue;
        if (!looksPb(buf) && !hasMark(buf)) continue;
        seen[k]=1;
        out.push({src:label+'_off0x'+off.toString(16), addr:pv, hex:toHex(buf),
                  mark: hasMark(buf), pb: looksPb(buf)});
    }
}

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (hits >= 10) return;
        var a2v = args[2];
        var chk = a2HasBeforeCompress(a2v);
        if (!chk.ok) return;
        var N = chk.N;
        hits++;

        var cands = [], seen = {};
        for (var ai=0; ai<8; ai++) {
            try { collectFromObj(args[ai], 'arg'+ai, N, cands, seen); } catch(e) {}
        }
        // 栈：esp 上下各 4KB
        var esp = this.context.esp;
        for (var si=-4096; si<4096; si+=4) {
            var pv2 = u32(esp, si);
            if (!isHeap(pv2)) continue;
            var k2 = pv2.toString(16);
            if (seen[k2]) continue;
            var buf2 = readN(ptr(pv2), N);
            if (!buf2) continue;
            if (!looksPb(buf2) && !hasMark(buf2)) continue;
            seen[k2]=1;
            cands.push({src:'stack_esp'+si, addr:pv2, hex:toHex(buf2),
                        mark: hasMark(buf2), pb: looksPb(buf2)});
        }

        send({t:'hit', n:hits, N:N,
              a2_excerpt: chk.excerpt,
              args: [0,1,2,3,4].map(function(i){ return args[i].toString(); }),
              cands: cands});
    }
});
send({t:'ready'});
"""

def pb_fields(data):
    fields=[]; i=0
    while i<len(data) and len(fields)<30:
        if data[i]==0: break
        try:
            tag=0; sh=0
            while i<len(data):
                b=data[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                if not(b&0x80): break
            wire=tag&7; f=tag>>3
            if f==0 or f>10000: break
            if wire==0:
                v=0; sh2=0
                while i<len(data):
                    b=data[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                fields.append((f,v,'v'))
            elif wire==2:
                ln=0; sh2=0
                while i<len(data):
                    b=data[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                if ln>500000 or i+ln>len(data): break
                pay=data[i:i+ln]; i+=ln
                try: fields.append((f,pay.decode('utf-8')[:80],'s'))
                except: fields.append((f,pay[:16].hex(),'b'))
            elif wire==5: i+=4
            elif wire==1: i+=8
            else: break
        except: break
    return fields

def get_pid():
    o=subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

ts=datetime.now().strftime('%Y%m%d_%H%M%S')
ndjson=OUT_DIR/f'cgi_final_{ts}.ndjson'

def on_msg(msg, data):
    if msg.get('type')=='error':
        print('[ERR]', msg.get('description','')[:300], flush=True); return
    if msg.get('type')!='send': return
    p=msg['payload']
    if p.get('t')=='ready':
        print('[+] ready — 请发文字/文件', flush=True); return
    if p.get('t')!='hit': return
    N=p['N']; cands=p.get('cands',[])
    print(f'\n★ HIT #{p["n"]} N={N} cands={len(cands)} args={p["args"]}', flush=True)
    if p.get('a2_excerpt'): print(f'  a2: {p["a2_excerpt"][:160]}', flush=True)
    marks=[c for c in cands if c.get('mark')]
    if marks: print(f'  ★★★ MARK命中 {len(marks)}', flush=True)
    for i,c in enumerate(cands):
        raw=bytes.fromhex(c['hex'])
        flds=pb_fields(raw)
        flag=''
        if c.get('mark'): flag+=' ★MARK★'
        if len(flds)>=6: flag+=' ✦'
        print(f'  [{i}] {c["src"]} @0x{c["addr"]:x} pb={len(flds)}{flag}', flush=True)
        for f in flds[:8]:
            if f[2]=='s': print(f'    f{f[0]}: {f[1]!r}')
            elif f[2]=='v': print(f'    f{f[0]}={f[1]}')
        fn=OUT_DIR/f'cgi_final_{ts}_h{p["n"]}_c{i}.bin'
        fn.write_bytes(raw)
        if c.get('mark') or len(flds)>=8:
            print(f'    → {fn.name}', flush=True)
    with ndjson.open('a',encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

print('[*] attach...', flush=True)
pid=get_pid(); print(f'PID={pid}', flush=True)
sess=frida.get_local_device().attach(pid)
sc=sess.create_script(JS); sc.on('message', on_msg); sc.load()
time.sleep(CAPTURE_SEC)
try: sc.unload()
except: pass
try: sess.detach()
except: pass
print('[+] done', flush=True)
os._exit(0)
