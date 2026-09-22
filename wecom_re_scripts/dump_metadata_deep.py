# dump_metadata_deep.py
# Hook 0x390CE0，转发时深入 dump metadata(+52) 及所有内层指针
import frida, subprocess, sys, os, time, json, struct
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
MAGIC = bytes([0xd0, 0x07, 0x00, 0x02])

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
var wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
var wxBase = wx.base;
send({t:'base', v:wxBase.toString()});

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

var startTs = Date.now();
var baseline = {};
var phase = 1;
var results = [];

function collectPtrs(bs, maxN) {
    var out = [];
    if (!bs) return out;
    for (var i = 0; i + 3 < bs.length; i += 4) {
        var pv = (bs[i]) | (bs[i+1]<<8) | (bs[i+2]<<16) | (bs[i+3]<<24);
        pv = pv >>> 0;
        if (pv > 0x10000000 && pv < 0x7F000000) {
            out.push({off:i, ptr:'0x'+pv.toString(16)});
            if (out.length >= maxN) break;
        }
    }
    return out;
}

Interceptor.attach(wxBase.add(0x390ce0), {
    onEnter: function(args) {
        if (phase !== 2) {
            if (phase === 1) {
                var b1 = args[1].toInt32() >>> 0;
                baseline['0x'+b1.toString(16)] = true;
            }
            return;
        }
        var elapsed = Date.now() - startTs;
        var beginV = args[1].toInt32() >>> 0;
        var endV = args[2].toInt32() >>> 0;
        var bk = '0x' + beginV.toString(16);
        if (baseline[bk]) return;
        if (results.some(function(r){ return r.begin === bk; })) return;

        var sz = endV - beginV;
        if (sz <= 0 || sz > 512) return;
        var task = safeR(beginV, sz);
        if (!task || task.length < 56) return;

        var metaPtr = (task[52]) | (task[53]<<8) | (task[54]<<16) | (task[55]<<24);
        metaPtr = metaPtr >>> 0;
        var meta = safeR(metaPtr, 1024);
        if (!meta) return;

        // 找 magic
        var magicOff = -1;
        for (var i = 0; i + 3 < meta.length; i++) {
            if (meta[i]===0xd0 && meta[i+1]===0x07 && meta[i+2]===0x00 && meta[i+3]===0x02) {
                magicOff = i; break;
            }
        }

        var tag4 = '';
        if (magicOff >= 0 && magicOff + 28 <= meta.length) {
            tag4 = String.fromCharCode(meta[magicOff+24], meta[magicOff+25], meta[magicOff+26], meta[magicOff+27]);
        }

        var u32_0 = (meta[0])|(meta[1]<<8)|(meta[2]<<16)|(meta[3]<<24)>>>0;
        var u32_1 = (meta[4])|(meta[5]<<8)|(meta[6]<<16)|(meta[7]<<24)>>>0;

        var ptrs = collectPtrs(meta, 16);
        var deep = [];
        ptrs.forEach(function(p) {
            var pv = parseInt(p.ptr, 16);
            var d = safeR(pv, 1024);
            if (d) deep.push({fromOff:p.off, ptr:p.ptr, bytes:d});
        });

        // task 内其他指针
        var taskPtrs = collectPtrs(task, 8);
        taskPtrs.forEach(function(p) {
            if (p.off === 52) return;
            var pv = parseInt(p.ptr, 16);
            var d = safeR(pv, 512);
            if (d) deep.push({fromOff:'task+'+p.off, ptr:p.ptr, bytes:d});
        });

        results.push({
            elapsed: elapsed, begin: bk, sz: sz,
            metaPtr: '0x'+metaPtr.toString(16),
            u32_0: u32_0, u32_1: u32_1,
            magicOff: magicOff, tag4: tag4,
            meta: meta, deep: deep
        });
        send({t:'hit', begin:bk, tag4:tag4, u32_1:u32_1, elapsed:elapsed});
    }
});

recv('phase2', function(_) { phase = 2; send({t:'go'}); });
recv('dump', function(_) { send({t:'dump', results:results}); });
send({t:'ready'});
"""

results = []
dump_ok = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    t = p.get('t','')
    if t == 'base':
        print(f'  wxBase={p["v"]}')
    elif t == 'ready':
        print('[+] Hook ready')
    elif t == 'go':
        print('[+] Phase 2 GO')
    elif t == 'hit':
        print(f'  ★ {p["begin"]} tag4={repr(p["tag4"])} count={p["u32_1"]} t={p["elapsed"]/1000:.1f}s')
    elif t == 'dump':
        results.extend(p.get('results', []))
        dump_ok[0] = True

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b&0x7F)<<sh; sh += 7
        if not (b&0x80): return v, pos
    return None, pos

def parse_proto(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 40:
        if bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag&7; fn = tag>>3
            if fn==0 or fn>5000: break
            if w==0:
                v,i = decode_varint(bs,i)
                if v is None: break
                fields.append((fn,'v',v))
            elif w==2:
                ln,i2 = decode_varint(bs,i)
                if ln is None or ln>100000 or i2+ln>len(bs): break
                pay=bs[i2:i2+ln]; i=i2+ln
                try: fields.append((fn,'s',pay.decode('utf-8')))
                except: fields.append((fn,'b',pay[:32].hex()))
            elif w==5:
                if i+4<=len(bs): i+=4; fields.append((fn,'i32',0))
                else: break
            elif w==1:
                if i+8<=len(bs): i+=8; fields.append((fn,'i64',0))
                else: break
            else: break
        except: break
    return fields

def scan_compacts(bs):
    hits = []
    for i in range(len(bs)-3):
        if bs[i]==0x01 and not (bs[i+1]==0 and bs[i+2]==0 and bs[i+3]==0):
            hits.append((i, bs[i:i+4].hex()))
    return hits

def scan_large_varints(bs):
    hits = []
    for i in range(min(len(bs), 512)):
        v, j = decode_varint(bs, i)
        if v and v > 10000:
            hits.append((i, v))
    return hits[:10]

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1.5)

print('\n[Phase 1] 8s baseline...')
time.sleep(8)
sc.post({'type':'phase2'})
time.sleep(0.2)

print('\n' + '='*60)
print('>>> 请立即在企微转发 1 条消息 <<<')
print('='*60)

t0 = time.time()
while time.time()-t0 < 60 and len(results) < 5:
    time.sleep(0.5)
time.sleep(2)

sc.post({'type':'dump'})
t1 = time.time()
while not dump_ok[0] and time.time()-t1 < 5:
    time.sleep(0.2)

print(f'\n[分析] {len(results)} 个新 task')

for r in results:
    print(f'\n{"="*70}')
    print(f'begin={r["begin"]} meta={r["metaPtr"]} tag4={repr(r["tag4"])} subcount={r["u32_1"]}')
    meta = bytes(r.get('meta') or [])
    if meta:
        mo = r.get('magicOff', -1)
        if mo >= 0:
            print(f'  magic@+{mo}: {meta[mo:mo+32].hex()}')
        comps = scan_compacts(meta)
        if comps:
            print(f'  metadata compacts: {comps[:8]}')
        big = scan_large_varints(meta)
        if big:
            print(f'  metadata large varints: {big}')
        pf = parse_proto(meta)
        if pf:
            print('  metadata proto:')
            for fn,wt,v in pf[:10]:
                if wt=='v': print(f'    f{fn}={v} (0x{v:x})')
                elif wt=='s': print(f'    f{fn}={repr(v[:60])}')
                else: print(f'    f{fn}={wt}:{v}')

    for d in r.get('deep', []):
        bs = bytes(d.get('bytes') or [])
        if not bs or all(b==0 for b in bs[:32]):
            continue
        comps = scan_compacts(bs)
        pf = parse_proto(bs)
        big = scan_large_varints(bs)
        has_f13 = any(fn==13 for fn,_,v in pf if isinstance(v,int)) if pf else False
        if not comps and not pf and not big:
            continue
        print(f'\n  deep from {d["fromOff"]} -> {d["ptr"]}:')
        print(f'    head64: {bs[:64].hex()}')
        if comps:
            print(f'    compacts: {comps[:6]}')
        if big:
            print(f'    large varints: {big}')
        if pf:
            print(f'    proto ({len(pf)} fields):')
            for fn,wt,v in pf[:15]:
                mark = ' ★' if fn==13 else ''
                if wt=='v': print(f'      f{fn}={v}{mark}')
                elif wt=='s': print(f'      f{fn}={repr(v[:50])}{mark}')
                else: print(f'      f{fn}={wt}:{v}{mark}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'metadata_deep_{ts}.json'
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] Saved: {out}')

sc.unload()
sess.detach()
os._exit(0)
