# cgi_proto_dump3.py — P0: 从 args[1] + arg2 + 多帧 EBP 钉死 before-compress proto
#
# v2 遗漏：args[1]=0x25df0068 跨 HIT 稳定不变，极可能是 CGI 请求对象本体
# 本版策略：
#   1. hook wxBase+0x963E58A，过滤 cgi request:1001 + before compress
#   2. 解析 N，优先扫 args[1] 8KB（MSVC std::string: ptr@+0 size@+16）
#   3. 扫 arg2 4KB 同样 layout
#   4. 沿 EBP 链向上 8 帧，每帧 4KB
#   5. args[1]/arg2 内所有 heap 指针 → 再扫 size==N
#   6. 命中含 1688855 / S: / conversation 的候选标 ★CID★
#
# 禁止：M3 / mitmproxy / SSL_write 主线

import frida, subprocess, sys, os, time, json, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CAPTURE_SEC = 90

JS = r"""
'use strict';
var wxBase  = Process.getModuleByName('WXWork.exe').base;
var hookPtr = wxBase.add(0x963E58A);
var n = 0, MAX = 20;

function u32(a, i) {
    return ((a[i]|(a[i+1]<<8)|(a[i+2]<<16)|(a[i+3]<<24))>>>0);
}
function safeBytes(addr, sz) {
    try {
        var p = ptr(addr);
        var v = p.toUInt32();
        if (v < 0x10000 || v > 0x7F000000) return null;
        return p.readByteArray(sz);
    } catch(e) { return null; }
}
function toHex(ab) {
    var a = new Uint8Array(ab), s = '';
    for (var i = 0; i < a.length; i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}
function asciiStr(ab) {
    var a = new Uint8Array(ab), out = [], run = '', start = 0;
    for (var i = 0; i < a.length; i++) {
        if (a[i] >= 0x20 && a[i] <= 0x7E) {
            if (!run.length) start = i;
            run += String.fromCharCode(a[i]);
        } else {
            if (run.length >= 6) out.push(run);
            run = '';
        }
    }
    if (run.length >= 6) out.push(run);
    return out;
}
function isHeap(v) {
    return v > 0x00400000 && v < 0x7F000000;
}
// MSVC std::string 32bit: ptr@off-16, size@off, cap@off+4
function findStdStringN(ab, N, label) {
    var a = new Uint8Array(ab);
    var NL=(N&0xFF), N1=((N>>8)&0xFF), N2=((N>>16)&0xFF), N3=((N>>24)&0xFF);
    var found = [];
    for (var i = 0; i + 3 < a.length; i += 4) {
        if (a[i]!==NL||a[i+1]!==N1||a[i+2]!==N2||a[i+3]!==N3) continue;
        // layout A: size at i, ptr at i-16
        if (i >= 16) {
            var pv = u32(a, i-16);
            if (isHeap(pv)) found.push({src: label+'_str16_off'+i, p: pv});
        }
        // layout B: ptr at i-4, size at i (compact pair)
        if (i >= 4) {
            var pv2 = u32(a, i-4);
            if (isHeap(pv2)) found.push({src: label+'_adj_off'+i, p: pv2});
        }
        // layout C: size at i, ptr at i+4 (reversed?)
        if (i + 4 <= a.length) {
            var pv3 = u32(a, i+4);
            if (isHeap(pv3)) found.push({src: label+'_post_off'+i, p: pv3});
        }
    }
    return found;
}
function heapPtrs(ab, limit) {
    var a = new Uint8Array(ab), seen = {}, out = [];
    for (var i = 0; i+3 < a.length && out.length < (limit||80); i += 4) {
        var pv = u32(a, i);
        if (!isHeap(pv)) continue;
        var k = pv.toString(16);
        if (!seen[k]) { seen[k]=1; out.push({p:pv, off:i}); }
    }
    return out;
}

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (n >= MAX) return;

        var a2v = args[2].toUInt32();
        var a2raw = safeBytes(a2v, 4096);
        if (!a2raw) return;
        var a2join = asciiStr(a2raw).join('|');
        if (a2join.indexOf('cgi request:1001') < 0 || a2join.indexOf('before compress') < 0) return;

        var mN = a2join.match(/before compress length (\d+)/);
        if (!mN) return;
        var N = parseInt(mN[1]);
        n++;

        var candidates = [];
        var seen = {};

        function addCandidate(addr, label) {
            if (!isHeap(addr)) return;
            var k = addr.toString(16);
            if (seen[k]) return;
            seen[k] = 1;
            var raw = safeBytes(addr, N);
            if (!raw) return;
            var hex = toHex(raw);
            // 快速特征检测
            var a = new Uint8Array(raw);
            var ascii = '';
            for (var i = 0; i < Math.min(a.length, 512); i++) {
                ascii += (a[i]>=0x20 && a[i]<0x7E) ? String.fromCharCode(a[i]) : '.';
            }
            var hasCID = ascii.indexOf('1688855') >= 0 || ascii.indexOf('S:1688') >= 0;
            var hasConv = ascii.indexOf('conversation') >= 0 || ascii.indexOf('Conversation') >= 0;
            candidates.push({
                src: label,
                addr: '0x'+addr.toString(16),
                hex: hex,
                dump_n: N,
                hasCID: hasCID,
                hasConv: hasConv,
                ascii_head: ascii.slice(0, 120)
            });
        }

        // ── 优先：args[1] 8KB ────────────────────────────────────────────────
        var a1v = args[1].toUInt32();
        var a1raw = safeBytes(a1v, 8192);
        if (a1raw) {
            var h1 = findStdStringN(a1raw, N, 'a1');
            for (var i = 0; i < h1.length && i < 12; i++) {
                addCandidate(h1[i].p, h1[i].src);
            }
            var p1 = heapPtrs(a1raw, 64);
            for (var j = 0; j < p1.length; j++) {
                addCandidate(p1[j].p, 'a1_ptr0x'+p1[j].p.toString(16)+'_off'+p1[j].off);
                // 二级：被指对象内再找 size==N
                var sub = safeBytes(p1[j].p, 2048);
                if (!sub) continue;
                var h2 = findStdStringN(sub, N, 'a1sub0x'+p1[j].p.toString(16));
                for (var k = 0; k < h2.length && k < 4; k++) {
                    addCandidate(h2[k].p, h2[k].src);
                }
            }
        }

        // ── arg2 4KB ───────────────────────────────────────────────────────
        var h2a = findStdStringN(a2raw, N, 'a2');
        for (var i2 = 0; i2 < h2a.length && i2 < 12; i2++) {
            addCandidate(h2a[i2].p, h2a[i2].src);
        }
        var p2 = heapPtrs(a2raw, 48);
        for (var j2 = 0; j2 < p2.length; j2++) {
            var sub2 = safeBytes(p2[j2].p, 2048);
            if (!sub2) continue;
            var h2b = findStdStringN(sub2, N, 'a2sub0x'+p2[j2].p.toString(16));
            for (var k2 = 0; k2 < h2b.length && k2 < 4; k2++) {
                addCandidate(h2b[k2].p, h2b[k2].src);
            }
        }

        // ── EBP 链 8 帧 ────────────────────────────────────────────────────
        var ebp = this.context.ebp;
        for (var fi = 0; fi < 8; fi++) {
            var fr = safeBytes(ebp, 4096);
            if (fr) {
                var hf = findStdStringN(fr, N, 'ebp'+fi+'_off'+ebp.toUInt32().toString(16));
                for (var hfi = 0; hfi < hf.length && hfi < 6; hfi++) {
                    addCandidate(hf[hfi].p, hf[hfi].src);
                }
            }
            var nextEbpRaw = safeBytes(ebp, 4);
            if (!nextEbpRaw) break;
            var nextEbp = u32(new Uint8Array(nextEbpRaw), 0);
            if (!nextEbp || nextEbp <= 0x10000 || nextEbp === ebp.toUInt32()) break;
            ebp = ptr(nextEbp);
        }

        // ── args[0/3/4] 直接 + size 扫描 ──────────────────────────────────
        for (var ai = 0; ai <= 4; ai++) {
            if (ai === 1 || ai === 2) continue;
            var av = args[ai].toUInt32();
            addCandidate(av, 'args['+ai+']@0x'+av.toString(16));
            var araw = safeBytes(av, 1024);
            if (!araw) continue;
            var ha = findStdStringN(araw, N, 'a'+ai);
            for (var hai = 0; hai < ha.length && hai < 4; hai++) {
                addCandidate(ha[hai].p, ha[hai].src);
            }
        }

        send({
            t: 'hit', n: n, N: N,
            args: [
                '0x'+args[0].toUInt32().toString(16),
                '0x'+args[1].toUInt32().toString(16),
                '0x'+args[2].toUInt32().toString(16),
                '0x'+args[3].toUInt32().toString(16),
                '0x'+args[4].toUInt32().toString(16)
            ],
            a2_excerpt: a2join.slice(0, 180),
            candidates: candidates
        });
    }
});

send({t:'ready', hook: hookPtr.toString(), base: wxBase.toString()});
"""

def pb_decode(data, depth=0, max_fields=300):
    fields=[]; i=0
    while i<len(data) and len(fields)<max_fields:
        if data[i]==0: break
        try:
            tag=0; sh=0
            while i<len(data):
                b=data[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                if not(b&0x80): break
            wire=tag&7; fnum=tag>>3
            if fnum==0 or fnum>100000: break
            if wire==0:
                v=0; sh2=0
                while i<len(data):
                    b=data[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                fields.append({'f':fnum,'w':'v','v':v})
            elif wire==2:
                ln=0; sh2=0
                while i<len(data):
                    b=data[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                if ln<0 or ln>500000 or i+ln>len(data): break
                pay=data[i:i+ln]; i+=ln
                try:
                    s=pay.decode('utf-8')
                    fields.append({'f':fnum,'w':'s','v':s})
                except:
                    sub=pb_decode(pay,depth+1,40) if depth<3 else None
                    fields.append({'f':fnum,'w':'b','len':ln,'hex':pay[:20].hex(),'sub':sub})
            elif wire==5: i+=4
            elif wire==1: i+=8
            else: break
        except: break
    return fields

def pb_score(fields):
    s=0
    for f in fields:
        s+=1
        if f['w']=='s': s+=max(0,min(len(f['v']),60))//4
        if f.get('sub'): s+=3
    return s

def print_fields(fields, indent=0):
    pfx='  '*indent
    for f in fields[:20]:
        if f['w']=='s': print(f"{pfx}  f{f['f']}(str): {repr(f['v'][:100])}")
        elif f['w']=='v': print(f"{pfx}  f{f['f']}(int): {f['v']}")
        elif f['w']=='b':
            print(f"{pfx}  f{f['f']}(bytes,{f['len']}): {f['hex']}")
            if f.get('sub'): print_fields(f['sub'], indent+1)

def get_pid():
    o=subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            pid=int(line.strip().split()[-1])
            print(f'  :9882 → PID={pid}'); return pid
    raise RuntimeError('未找到 :9882')

ts_str=datetime.now().strftime('%Y%m%d_%H%M%S')
ndjson_p=OUT_DIR/f'cgi_proto3_{ts_str}.ndjson'
hits_all=[]

def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p=msg['payload']; t=p.get('t','')
    if t=='ready':
        print(f'[+] HOOK @ {p.get("hook")}  base={p.get("base")}', flush=True); return
    if t!='hit': return

    cap=p; hits_all.append(cap)
    N=cap['N']; cands=cap.get('candidates',[])
    print(f'\n{"="*72}', flush=True)
    print(f'★ HIT #{cap["n"]}  N={N}  args={cap["args"]}', flush=True)
    print(f'  a2: {cap.get("a2_excerpt","")[:160]}', flush=True)
    print(f'  候选: {len(cands)}', flush=True)

    cid_hits=[c for c in cands if c.get('hasCID') or c.get('hasConv')]
    if cid_hits:
        print(f'  ★★★ CID 命中 {len(cid_hits)} 个！', flush=True)

    for ci,c in enumerate(cands):
        raw=bytes.fromhex(c['hex'])
        fields=pb_decode(raw); score=pb_score(fields)
        flag=''
        if c.get('hasCID'): flag+=' ★CID★'
        if c.get('hasConv'): flag+=' ★CONV★'
        if score>=8: flag+=' ✦PB✦'
        print(f'\n  [{ci}] {c["src"]}  addr={c["addr"]}  score={score}  pb={len(fields)}{flag}', flush=True)
        if c.get('ascii_head') and (c.get('hasCID') or score>=5):
            print(f'    ascii: {c["ascii_head"][:100]!r}', flush=True)
        if fields and (score>=5 or c.get('hasCID')):
            print_fields(fields[:15], indent=1)
        bin_name=f'cgi_proto3_{ts_str}_h{cap["n"]}_c{ci}.bin'
        (OUT_DIR/bin_name).write_bytes(raw)
        if c.get('hasCID') or score>=10:
            print(f'    → ★ {bin_name}', flush=True)

    with ndjson_p.open('a',encoding='utf-8') as f:
        f.write(json.dumps(cap, ensure_ascii=False)+'\n')

print('[*] 获取 PID...', flush=True)
pid=get_pid()
print('[*] Attaching...', flush=True)
sess=frida.get_local_device().attach(pid)
sc=sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

print(f'\n{"="*72}', flush=True)
print(f'★★★ 请在 {CAPTURE_SEC}s 内再发一条【文字】或【文件】', flush=True)
print(f'    重点扫 args[1]=CGI对象；出现 ★CID★ = 成功', flush=True)
print(f'{"="*72}', flush=True)

time.sleep(CAPTURE_SEC)
try:
    sc.unload()
except Exception:
    pass
try:
    sess.detach()
except Exception:
    pass

print(f'\n[+] 共 {len(hits_all)} 次命中  →  {ndjson_p}', flush=True)
os._exit(0)
