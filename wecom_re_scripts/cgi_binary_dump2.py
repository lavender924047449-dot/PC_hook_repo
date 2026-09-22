# cgi_binary_dump2.py — 改进版：加调用者栈帧扫描 + 过滤 ASCII 假指针
#
# 主要改进（相对 cgi_binary_dump.py）：
#  1. 用 this.context.esp / ebp 扫 CALLER 的局部变量区（proto std::string 在那里）
#  2. heapPtrsIn 只扫二进制（非纯 ASCII）区域，避免 UUID 字节成假阳性
#  3. 追 args[4] 内第一层指针 → 各 dump N 字节（args[4] 可能是 task/iter 容器）
#  4. 扫 args[0] (可能是 this/CGI对象) 的前 1KB
#  5. 对每个候选做 proto decode 同时也试 +0 到 +64 各 4B 偏移起点
#
# 禁止：M3 / mitmproxy / 系统代理 / SSL_write 主线 / builder RVA 0x99235A0

import frida, subprocess, sys, os, time, json, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR      = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
F2_TOP_RVA   = 0x963E58A
CAPTURE_SEC  = 90
MAX_CAP      = 20

JS = r"""
'use strict';
var wxBase  = Process.getModuleByName('WXWork.exe').base;
var hookPtr = wxBase.add(0x963E58A);
var n = 0;
var MAX = 20;

// ── 工具 ──────────────────────────────────────────────────────────────────────

function u32(a, i) {
    return ((a[i] | (a[i+1]<<8) | (a[i+2]<<16) | (a[i+3]<<24)) >>> 0);
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
    var a = new Uint8Array(ab);
    var s = '';
    for (var i = 0; i < a.length; i++) s += ('0'+a[i].toString(16)).slice(-2);
    return s;
}

function asciiStr(ab) {
    var a = new Uint8Array(ab);
    var strs = [], run = '', start = 0;
    for (var i = 0; i < a.length; i++) {
        if (a[i] >= 0x20 && a[i] <= 0x7E) {
            if (!run.length) start = i;
            run += String.fromCharCode(a[i]);
        } else {
            if (run.length >= 6) strs.push({o: start, s: run});
            run = '';
        }
    }
    if (run.length >= 6) strs.push({o: start, s: run});
    return strs;
}

// 找 dword==N (LE) 并在偏移-16 或偏移-4 找 heap ptr（MSVC std::string layout）
function findSizeN(ab, N) {
    var a = new Uint8Array(ab);
    var NL=(N&0xFF), N1=((N>>8)&0xFF), N2=((N>>16)&0xFF), N3=((N>>24)&0xFF);
    var found = [];
    for (var i = 0; i+3 < a.length; i += 4) {
        if (a[i]!==NL||a[i+1]!==N1||a[i+2]!==N2||a[i+3]!==N3) continue;
        // MSVC std::string 32bit: ptr at offset-16, size at offset 0
        if (i >= 16) {
            var pv = u32(a, i-16);
            if (pv>0x00400000 && pv<0x7F000000)
                found.push({off:i, src:'str+16', p:pv});
        }
        // adjacent ptr/size pair
        if (i >= 4) {
            var pv2 = u32(a, i-4);
            if (pv2>0x00400000 && pv2<0x7F000000)
                found.push({off:i, src:'adj', p:pv2});
        }
        // also i+4 might be capacity — ptr already covered by i-16
    }
    return found;
}

// 只扫非-全ASCII区域的 heap 指针（避免 UUID 字节成假阳性）
function binaryHeapPtrs(ab, limit) {
    var a = new Uint8Array(ab);
    var seen = {}, out = [];
    for (var i = 0; i+3 < a.length && out.length < (limit||64); i += 4) {
        // 如果 4 字节都是 printable ASCII (0x20-0x7E)，跳过
        if (a[i]>=0x20&&a[i]<=0x7E && a[i+1]>=0x20&&a[i+1]<=0x7E &&
            a[i+2]>=0x20&&a[i+2]<=0x7E && a[i+3]>=0x20&&a[i+3]<=0x7E) continue;
        var pv = u32(a, i);
        // 32-bit user-space heap: 0x00400000 - 0x7F000000
        if (pv > 0x00400000 && pv < 0x7F000000) {
            var k = pv.toString(16);
            if (!seen[k]) { seen[k]=1; out.push(pv); }
        }
    }
    return out;
}

// ── Hook ──────────────────────────────────────────────────────────────────────

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (n >= MAX) return;

        // 读 arg2 (log 上下文，2KB)
        var a2v = args[2].toUInt32();
        var a2raw = safeBytes(a2v, 2048);
        if (!a2raw) return;

        var a2str = asciiStr(a2raw).map(function(x){return x.s;}).join('|');
        if (a2str.indexOf('cgi request:1001') < 0 || a2str.indexOf('before compress') < 0) return;

        var mN = a2str.match(/before compress length (\d+)/);
        if (!mN) return;
        var N = parseInt(mN[1]);
        n++;

        var candidates = [];
        var seen = {};

        function tryAddr(addr, label, offset) {
            offset = offset || 0;
            if (!addr || addr < 0x10000 || addr > 0x7F000000) return;
            var realAddr = addr + offset;
            if (realAddr < 0x10000 || realAddr > 0x7F000000) return;
            var k = realAddr.toString(16);
            if (seen[k]) return; seen[k]=1;
            var raw = safeBytes(realAddr, N + 256);
            if (!raw) return;
            candidates.push({
                src: label + (offset?'+'+offset:''),
                addr: '0x'+realAddr.toString(16),
                hex: toHex(raw).slice(0, (N+256)*2),
                dump_n: N
            });
        }

        // ── 策略 A: args[3] / args[4] 直接 + 偏移 0/4/8/16 ──────────────────
        for (var ai = 3; ai <= 4; ai++) {
            var av = args[ai].toUInt32();
            tryAddr(av, 'args['+ai+']@0x'+av.toString(16));
            // 追 args[ai] 内部第一层指针（args[4] 可能是 iterator 或 task 对象）
            var airaw = safeBytes(av, 256);
            if (airaw) {
                var aiptrs = binaryHeapPtrs(airaw, 16);
                for (var pi=0; pi<aiptrs.length; pi++) {
                    tryAddr(aiptrs[pi], 'args['+ai+']_ptr0x'+aiptrs[pi].toString(16));
                }
            }
        }

        // ── 策略 B: 调用者栈帧（★ 新增）─────────────────────────────────────
        // 在 f2_top 入口 (prologue 未执行)：
        //   esp → return addr
        //   esp+4..20 → args[0..4]
        //   esp+24 起 → 调用者的局部变量（proto std::string 在此）
        //   ebp → 调用者的 EBP（未变，f2_top prologue 还没 push ebp）
        var espV = this.context.esp;
        var ebpV = this.context.ebp;

        // 调用者局部变量区：从 (esp+24) 到 ebp（或最多 2KB）
        var callerFrameStart = espV.add(24);
        var callerFrameSize  = Math.min(ebpV.sub(callerFrameStart).toUInt32(), 2048);
        if (callerFrameSize > 8 && callerFrameSize < 65536) {
            var cfRaw = safeBytes(callerFrameStart, callerFrameSize);
            if (cfRaw) {
                // 找 dword==N → std::string
                var cfHits = findSizeN(cfRaw, N);
                for (var hi=0; hi<cfHits.length && hi<8; hi++) {
                    tryAddr(cfHits[hi].p, 'caller_frame_'+cfHits[hi].src+'_off'+cfHits[hi].off);
                }
                // 也直接 dump 帧内找到的 heap 指针
                var cfPtrs = binaryHeapPtrs(cfRaw, 32);
                for (var pi2=0; pi2<cfPtrs.length && pi2<16; pi2++) {
                    tryAddr(cfPtrs[pi2], 'caller_frame_ptr0x'+cfPtrs[pi2].toString(16));
                }
            }
        }

        // 调用者 EBP 上方也扫（EBP 之上是调用者的父调用者参数等）
        var ebpRaw = safeBytes(ebpV, 512);
        if (ebpRaw) {
            var ebpHits = findSizeN(ebpRaw, N);
            for (var hi2=0; hi2<ebpHits.length && hi2<4; hi2++) {
                tryAddr(ebpHits[hi2].p, 'ebp_up_'+ebpHits[hi2].src+'_off'+ebpHits[hi2].off);
            }
        }

        // ── 策略 C: args[0] (可能是 CGI 对象 this) ───────────────────────────
        var a0v = args[0].toUInt32();
        var a0raw = safeBytes(a0v, 1024);
        if (a0raw) {
            var a0hits = findSizeN(a0raw, N);
            for (var hi3=0; hi3<a0hits.length && hi3<4; hi3++) {
                tryAddr(a0hits[hi3].p, 'args[0]_str_'+a0hits[hi3].src+'_off'+a0hits[hi3].off);
            }
        }

        // ── 策略 D: 扫 arg2 中的真实 heap 指针（过滤 ASCII 假阳性）──────────
        var a2ptrs = binaryHeapPtrs(a2raw, 32);
        for (var pi3=0; pi3<a2ptrs.length; pi3++) {
            var pv3 = a2ptrs[pi3];
            // 扫被指对象找 size==N
            var praw = safeBytes(pv3, 512);
            if (!praw) continue;
            var phits = findSizeN(praw, N);
            for (var hk=0; hk<phits.length && hk<2; hk++) {
                tryAddr(phits[hk].p, 'a2ptr0x'+pv3.toString(16)+'_'+phits[hk].src+'_off'+phits[hk].off);
            }
        }

        // ── 策略 E: arg2 的 findSizeN 直扫 ──────────────────────────────────
        var a2hits = findSizeN(a2raw, N);
        for (var hi4=0; hi4<a2hits.length && hi4<6; hi4++) {
            tryAddr(a2hits[hi4].p, 'a2scan_'+a2hits[hi4].src+'_off'+a2hits[hi4].off);
        }

        // ── 发送 ──────────────────────────────────────────────────────────────
        send({
            t: 'hit',
            n: n, N: N,
            args: [
                '0x'+args[0].toUInt32().toString(16),
                '0x'+args[1].toUInt32().toString(16),
                '0x'+args[2].toUInt32().toString(16),
                '0x'+args[3].toUInt32().toString(16),
                '0x'+args[4].toUInt32().toString(16)
            ],
            esp: '0x'+espV.toUInt32().toString(16),
            ebp: '0x'+ebpV.toUInt32().toString(16),
            caller_frame_size: callerFrameSize,
            a2_excerpt: a2str.slice(0, 200),
            candidates: candidates
        });
    }
});

send({t:'ready', hook: hookPtr.toString(), base: wxBase.toString()});
"""

# ──────────────────────────────────────────────────────────────────────────────
# Python：protobuf 解码 + 写文件
# ──────────────────────────────────────────────────────────────────────────────

def pb_decode(data: bytes, depth=0, max_fields=300) -> list:
    fields = []; i = 0
    while i < len(data) and len(fields) < max_fields:
        if data[i] == 0: break
        try:
            tag=0; sh=0
            while i < len(data):
                b=data[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                if not(b&0x80): break
                if sh>35: raise ValueError
            wire=tag&7; fnum=tag>>3
            if fnum==0 or fnum>100000: break
            if wire==0:
                v=0; sh2=0
                while i<len(data):
                    b=data[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                fields.append({'f':fnum,'w':'varint','v':v})
            elif wire==1:
                if i+8>len(data): break
                v=int.from_bytes(data[i:i+8],'little'); i+=8
                fields.append({'f':fnum,'w':'i64','v':hex(v)})
            elif wire==2:
                ln=0; sh2=0
                while i<len(data):
                    b=data[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                if ln<0 or ln>500000 or i+ln>len(data): break
                pay=data[i:i+ln]; i+=ln
                try:
                    s=pay.decode('utf-8')
                    fields.append({'f':fnum,'w':'str','v':s})
                except:
                    sub=pb_decode(pay,depth+1,50) if depth<3 else None
                    fields.append({'f':fnum,'w':'bytes','len':ln,'hex':pay[:24].hex(),'sub':sub})
            elif wire==5:
                if i+4>len(data): break
                v=int.from_bytes(data[i:i+4],'little'); i+=4
                fields.append({'f':fnum,'w':'i32','v':hex(v)})
            else: break
        except: break
    return fields

def pb_score(fields):
    s=0
    for f in fields:
        s+=1
        if f['w']=='str': s+=max(0,min(len(f['v']),60))//4
        if f['w']=='varint' and 0<f['v']<0x7FFFFFFF: s+=1
        if f.get('sub') and len(f['sub'])>0: s+=3
    return s

def print_fields(fields, indent=0):
    pfx='  '*indent
    for f in fields[:25]:
        if f['w']=='str': print(f"{pfx}  f{f['f']}(str): {repr(f['v'][:120])}")
        elif f['w']=='varint': print(f"{pfx}  f{f['f']}(int): {f['v']}")
        elif f['w']=='bytes':
            print(f"{pfx}  f{f['f']}(bytes,{f['len']}): {f['hex']}"+(f" sub[{len(f['sub'])}]" if f.get('sub') else ''))
            if f.get('sub'): print_fields(f['sub'], indent+1)
        elif f['w'] in('i32','i64'): print(f"{pfx}  f{f['f']}({f['w']}): {f['v']}")

def get_pid():
    o=subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            pid=int(line.strip().split()[-1])
            print(f'  :9882 LISTENING → PID={pid}')
            return pid
    raise RuntimeError('未找到 :9882 LISTENING')

# ──────────────────────────────────────────────────────────────────────────────

ts_str   = datetime.now().strftime('%Y%m%d_%H%M%S')
ndjson_p = OUT_DIR / f'cgi_bin2_{ts_str}.ndjson'
hits_all = []

def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p=msg['payload']; t=p.get('t','')
    if t=='ready':
        print(f'[+] HOOK @ {p.get("hook")}  wxBase={p.get("base")}', flush=True); return
    if t!='hit': return

    cap=p; hits_all.append(cap)
    N=cap['N']; cands=cap.get('candidates',[])
    esp_hex=cap.get('esp','?'); ebp_hex=cap.get('ebp','?')
    cf_size=cap.get('caller_frame_size',0)

    print(f'\n{"="*72}', flush=True)
    print(f'★ HIT #{cap["n"]}  N={N}  args={cap["args"]}', flush=True)
    print(f'  esp={esp_hex}  ebp={ebp_hex}  caller_frame_size={cf_size}', flush=True)
    print(f'  a2: {cap.get("a2_excerpt","")[:160]}', flush=True)
    print(f'  候选数: {len(cands)}', flush=True)

    best_score=-1; best_src=None

    for ci,c in enumerate(cands):
        raw_hex=c.get('hex','')
        if not raw_hex: continue
        raw=bytes.fromhex(raw_hex[:N*2])
        fields=pb_decode(raw); score=pb_score(fields)
        has_str=sum(1 for f in fields if f['w']=='str')
        has_cid=any('1688855' in f.get('v','') for f in fields if f['w']=='str')

        flag=''
        if has_cid: flag=' ★CID★'
        if score>=5: flag+=' ✦'

        print(f'\n  [{ci}] {c["src"]}  addr={c["addr"]}  score={score}  pb={len(fields)}  str={has_str}{flag}', flush=True)
        if fields and score>=3:
            print_fields(fields[:12], indent=1)
        elif raw[:4]!=b'\x00\x00\x00\x00':
            print(f'    raw[0:32]={raw[:32].hex()}', flush=True)

        if score>best_score:
            best_score=score; best_src=c['src']

        bin_name=f'cgi_bin2_{ts_str}_h{cap["n"]}_c{ci}.bin'
        (OUT_DIR/bin_name).write_bytes(raw)
        print(f'    → {bin_name}', flush=True)

    if best_src:
        print(f'\n  ✔ 最佳: [{best_src}]  score={best_score}', flush=True)

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
print(f'★★★ 请在 {CAPTURE_SEC}s 内：', flush=True)
print(f'    1. 在企微发一条【文字消息】', flush=True)
print(f'    2. 再发一个【文件】或【转发】', flush=True)
print(f'    等待 HIT（有 ★CID★ 标志的候选 = 成功！）…', flush=True)
print(f'{"="*72}', flush=True)

time.sleep(CAPTURE_SEC)
sc.unload(); sess.detach()

print(f'\n[+] 共 {len(hits_all)} 次命中  ndjson={ndjson_p}', flush=True)
os._exit(0)
