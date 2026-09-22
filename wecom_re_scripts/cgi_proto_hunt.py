# cgi_proto_hunt.py — S2 · N 字节明文 proto 三路 hunt（第三十轮）
#
# 相对 cgi_binary_dump2.py 的增量：
#   策略 F: args[1] dedicated 8KB dump + findSizeN + binaryHeapPtrs（§46.8 明确遗漏）
#   策略 G: Thread.backtrace(ACCURATE) 上溯 f2_top 父/祖父帧，扫 size==N
#   策略 H: HIT 瞬间 Memory.scanSync 在 rw- 堆搜 dword==N + 相邻可读 heap ptr
#
# 目标：dump N 字节 明文 ChatRequestPackage protobuf；成功判据 = 候选 decode
#       后包含 "1688855042791155" 或 "S:1688" 前缀 conversationId。
#
# 安全约束（延续 §41–42）：本轮 P0 全程只读 onEnter，禁止任何代码段 patch。
# 禁止：M3 / mitmproxy / SSL_write 主线 / builder RVA 0x99235A0 优先。

import frida, subprocess, sys, os, time, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR      = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CAPTURE_SEC  = 180
MAX_CAP      = 6   # 每 HIT 一次 arena dump 512KB，控制上限避免爆内存

JS = r"""
'use strict';
var wxBase  = Process.getModuleByName('WXWork.exe').base;
var hookPtr = wxBase.add(0x963E58A);
var n = 0;
var MAX = 6;

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

// 找 dword==N 并在偏移-16/-4 找 heap ptr（MSVC std::string layout, 32bit）
function findSizeN(ab, N) {
    var a = new Uint8Array(ab);
    var NL=(N&0xFF), N1=((N>>8)&0xFF), N2=((N>>16)&0xFF), N3=((N>>24)&0xFF);
    var found = [];
    for (var i = 0; i+3 < a.length; i += 4) {
        if (a[i]!==NL||a[i+1]!==N1||a[i+2]!==N2||a[i+3]!==N3) continue;
        if (i >= 16) {
            var pv = u32(a, i-16);
            if (pv>0x00400000 && pv<0x7F000000)
                found.push({off:i, src:'str+16', p:pv});
        }
        if (i >= 4) {
            var pv2 = u32(a, i-4);
            if (pv2>0x00400000 && pv2<0x7F000000)
                found.push({off:i, src:'adj', p:pv2});
        }
        // 也试 i+4 是 ptr（有些容器把 size 放前）
        if (i+8 <= a.length) {
            var pv3 = u32(a, i+4);
            if (pv3>0x00400000 && pv3<0x7F000000)
                found.push({off:i, src:'i+4', p:pv3});
        }
    }
    return found;
}

function binaryHeapPtrs(ab, limit) {
    var a = new Uint8Array(ab);
    var seen = {}, out = [];
    for (var i = 0; i+3 < a.length && out.length < (limit||64); i += 4) {
        if (a[i]>=0x20&&a[i]<=0x7E && a[i+1]>=0x20&&a[i+1]<=0x7E &&
            a[i+2]>=0x20&&a[i+2]<=0x7E && a[i+3]>=0x20&&a[i+3]<=0x7E) continue;
        var pv = u32(a, i);
        if (pv > 0x00400000 && pv < 0x7F000000) {
            var k = pv.toString(16);
            if (!seen[k]) { seen[k]=1; out.push(pv); }
        }
    }
    return out;
}

// 判断是否像 protobuf: 第一字节的 field number ∈ [1, 200], wire type ∈ {0,1,2,5}
function looksLikeProto(addr, N) {
    try {
        var p = ptr(addr);
        var b0 = p.readU8();
        var wire = b0 & 7;
        var fnum = b0 >> 3;
        if (fnum < 1 || fnum > 200) return false;
        if (wire !== 0 && wire !== 1 && wire !== 2 && wire !== 5) return false;
        // 简单再验第 2 个 tag（如果 wire==2, 跳过 varint 长度）
        return true;
    } catch(e) { return false; }
}

// 策略 H (heap-wide scanSync) 已移除：会把 JS 线程锁 30s+ 导致 f2_top 高频路径卡死、
// send() 无法上抛、sc.unload() 阻塞。P0-C 需要时另写独立脚本。

// ── Hook ──────────────────────────────────────────────────────────────────────

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (n >= MAX) return;

        var a2v = args[2].toUInt32();
        var a2raw = safeBytes(a2v, 2048);
        if (!a2raw) return;

        var a2str = asciiStr(a2raw).map(function(x){return x.s;}).join('|');
        if (a2str.indexOf('cgi request:1001') < 0 || a2str.indexOf('before compress') < 0) return;

        var mN = a2str.match(/before compress length (\d+)/);
        if (!mN) return;
        var N = parseInt(mN[1]);
        n++;

        // ★ mini-heartbeat：一进 onEnter 立刻发，证明命中过（哪怕后续崩溃）
        send({t:'hb', n:n, N:N, a2_head: a2str.slice(0, 120)});

        var candidates = [];
        var seen = {};

        function tryAddr(addr, label) {
            if (!addr || addr < 0x10000 || addr > 0x7F000000) return;
            var k = addr.toString(16);  // dedupe by addr only, save many labels for same buf
            if (seen[k]) return; seen[k]=1;
            var raw = safeBytes(addr, N + 64);
            if (!raw) return;
            candidates.push({
                src: label,
                addr: '0x'+addr.toString(16),
                hex: toHex(raw).slice(0, (N+64)*2),
                looks_pb: looksLikeProto(addr, N)
            });
        }

        // ── A/B/C/D/E（沿用 v2）+ F/G/H（新增） ────────────────────────────

        // 策略 A: args[3]/args[4] 直接 + 一层指针
        for (var ai = 3; ai <= 4; ai++) {
            var av = args[ai].toUInt32();
            tryAddr(av, 'args['+ai+']');
            var airaw = safeBytes(av, 256);
            if (airaw) {
                var aiptrs = binaryHeapPtrs(airaw, 12);
                for (var pi=0; pi<aiptrs.length; pi++) {
                    tryAddr(aiptrs[pi], 'args['+ai+']_ptr0x'+aiptrs[pi].toString(16));
                }
            }
        }

        // 策略 B: 调用者栈帧
        var espV = this.context.esp;
        var ebpV = this.context.ebp;
        var callerFrameStart = espV.add(24);
        var callerFrameSize  = Math.min(ebpV.sub(callerFrameStart).toUInt32(), 4096);
        if (callerFrameSize > 8 && callerFrameSize < 65536) {
            var cfRaw = safeBytes(callerFrameStart, callerFrameSize);
            if (cfRaw) {
                var cfHits = findSizeN(cfRaw, N);
                for (var hi=0; hi<cfHits.length && hi<8; hi++) {
                    tryAddr(cfHits[hi].p, 'caller_'+cfHits[hi].src+'_off'+cfHits[hi].off);
                }
                var cfPtrs = binaryHeapPtrs(cfRaw, 20);
                for (var pi2=0; pi2<cfPtrs.length; pi2++) {
                    tryAddr(cfPtrs[pi2], 'caller_ptr0x'+cfPtrs[pi2].toString(16));
                }
            }
        }

        // 策略 C: args[0]
        var a0v = args[0].toUInt32();
        var a0raw = safeBytes(a0v, 1024);
        if (a0raw) {
            var a0hits = findSizeN(a0raw, N);
            for (var hi3=0; hi3<a0hits.length && hi3<4; hi3++) {
                tryAddr(a0hits[hi3].p, 'args[0]_str_'+a0hits[hi3].src+'_off'+a0hits[hi3].off);
            }
            // args[0] 内一层指针也各追一次 findSizeN
            var a0ptrs = binaryHeapPtrs(a0raw, 12);
            for (var pi3=0; pi3<a0ptrs.length; pi3++) {
                var praw2 = safeBytes(a0ptrs[pi3], 512);
                if (praw2) {
                    var phits2 = findSizeN(praw2, N);
                    for (var hk=0; hk<phits2.length && hk<2; hk++) {
                        tryAddr(phits2[hk].p, 'a0ptr0x'+a0ptrs[pi3].toString(16)+'_off'+phits2[hk].off);
                    }
                }
            }
        }

        // 策略 D: arg2 中 heap ptr
        var a2ptrs = binaryHeapPtrs(a2raw, 24);
        for (var pi4=0; pi4<a2ptrs.length; pi4++) {
            var pv4 = a2ptrs[pi4];
            var praw = safeBytes(pv4, 512);
            if (!praw) continue;
            var phits = findSizeN(praw, N);
            for (var hk2=0; hk2<phits.length && hk2<2; hk2++) {
                tryAddr(phits[hk2].p, 'a2ptr0x'+pv4.toString(16)+'_off'+phits[hk2].off);
            }
        }

        // 策略 E: arg2 findSizeN 直扫
        var a2hits = findSizeN(a2raw, N);
        for (var hi4=0; hi4<a2hits.length && hi4<6; hi4++) {
            tryAddr(a2hits[hi4].p, 'a2scan_'+a2hits[hi4].src+'_off'+a2hits[hi4].off);
        }

        // ── ★ 策略 F: args[1] dedicated 8KB dump + findSizeN + heap ptrs ────
        var a1v = args[1].toUInt32();
        var a1raw = safeBytes(a1v, 8192);
        if (a1raw) {
            var a1Hits = findSizeN(a1raw, N);
            for (var hi5=0; hi5<a1Hits.length && hi5<12; hi5++) {
                tryAddr(a1Hits[hi5].p, 'a1_str_'+a1Hits[hi5].src+'_off'+a1Hits[hi5].off);
            }
            // args[1] 内所有 heap ptr 都 8KB 展开再 findSizeN 一次
            var a1Ptrs = binaryHeapPtrs(a1raw, 30);
            for (var pi5=0; pi5<a1Ptrs.length; pi5++) {
                var pv5 = a1Ptrs[pi5];
                var pRaw = safeBytes(pv5, 1024);
                if (!pRaw) continue;
                var pH = findSizeN(pRaw, N);
                for (var hk3=0; hk3<pH.length && hk3<2; hk3++) {
                    tryAddr(pH[hk3].p, 'a1ptr0x'+pv5.toString(16)+'_off'+pH[hk3].off);
                }
            }
        }

        // ── ★ 策略 G: Thread.backtrace(ACCURATE) 上溯父/祖父帧 ──────────────
        var frames = [];
        var bt = [];
        try {
            bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8);
        } catch(e){}
        for (var fi=0; fi<bt.length; fi++) {
            var retAddr = bt[fi];
            var sym = DebugSymbol.fromAddress(retAddr);
            frames.push({
                i: fi,
                ret: retAddr.toString(),
                sym: (sym && sym.name) ? sym.name : ((sym && sym.moduleName) ? sym.moduleName+'!?' : '?')
            });
        }
        // 从 esp 向高地址扫 16KB，把每 4KB 的窗口逐个 findSizeN
        // （模拟"父/祖父帧的局部变量"，虽然帧边界不精确，但能覆盖到）
        var deepStart = espV;
        for (var dw=0; dw<4; dw++) {
            var dRaw = safeBytes(deepStart.add(dw*4096).toUInt32(), 4096);
            if (!dRaw) continue;
            var dHits = findSizeN(dRaw, N);
            for (var hi6=0; hi6<dHits.length && hi6<6; hi6++) {
                tryAddr(dHits[hi6].p, 'deepstk'+dw+'_'+dHits[hi6].src+'_off'+dHits[hi6].off);
            }
        }

        // 策略 H 已移除

        // ── ★ 策略 I: args[3] arena dump（每 HIT 一次 512KB，用 send 二进制通道）───
        // args[3] 疑似 CGI 自定义 slab arena（16MB 对齐 = 0x14d60000）。
        // 离线扫这 512KB 找 "1688855" / N 字节 proto 边界，一步到位。
        var arenaHex = null;
        var arenaBase = args[3].toUInt32();
        // 只 dump 前 512KB（arena 通常按低偏移分配新对象）
        var arenaRaw = safeBytes(arenaBase, 512 * 1024);
        if (arenaRaw) {
            // 走 send 的 data channel 而非塞进 JSON payload（性能）
            send({t:'arena', n:n, N:N, base:'0x'+arenaBase.toString(16), size:512*1024}, arenaRaw);
        }
        var scanRes = [];

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
            frames: frames,
            scan_summary: scanRes,
            cand_count: candidates.length,
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
        except Exception:
            break
    return fields

def pb_score(fields):
    s=0
    for f in fields:
        s+=1
        if f['w']=='str': s+=max(0,min(len(f['v']),60))//4
        if f['w']=='varint' and 0<f['v']<0x7FFFFFFF: s+=1
        if f.get('sub') and len(f['sub'])>0: s+=3
    return s

def fields_contain_cid(fields, depth=0):
    if depth > 4: return False
    for f in fields:
        if f['w']=='str' and ('1688855' in f['v'] or 'S:1688' in f['v']):
            return True
        if f.get('sub') and fields_contain_cid(f['sub'], depth+1):
            return True
    return False

def print_fields(fields, indent=0, max_shown=15):
    pfx='  '*indent
    for f in fields[:max_shown]:
        if f['w']=='str':
            v = f['v']
            marker = ' ★' if ('1688855' in v or 'S:1688' in v) else ''
            print(f"{pfx}  f{f['f']}(str): {repr(v[:120])}{marker}")
        elif f['w']=='varint': print(f"{pfx}  f{f['f']}(int): {f['v']}")
        elif f['w']=='bytes':
            print(f"{pfx}  f{f['f']}(bytes,{f['len']}): {f['hex']}"+(f" sub[{len(f['sub'])}]" if f.get('sub') else ''))
            if f.get('sub'): print_fields(f['sub'], indent+1, 8)
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
ndjson_p = OUT_DIR / f'cgi_hunt_{ts_str}.ndjson'
hits_all = []
found_cid = {'v': False, 'src': None, 'hit': None, 'ci': None}

def on_msg(msg, data):
    if msg.get('type')=='error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type')!='send': return
    p=msg['payload']; t=p.get('t','')
    if t=='ready':
        print(f'[+] HOOK @ {p.get("hook")}  wxBase={p.get("base")}', flush=True); return
    if t=='hb':
        print(f'  · heartbeat #{p["n"]} N={p["N"]}  a2_head={p.get("a2_head","")[:100]}', flush=True); return
    if t=='arena':
        # ★ 立刻落盘 arena 二进制（512KB）
        arena_name = f'cgi_hunt_{ts_str}_h{p["n"]}_arena.bin'
        (OUT_DIR/arena_name).write_bytes(data)
        # 在线扫 CID + N 字节 proto 边界
        idx_cid = data.find(b'1688855')
        idx_s = data.find(b'S:1688')
        print(f'  · arena #{p["n"]} base={p["base"]} 512KB → {arena_name}'
              f'  CID@{hex(idx_cid) if idx_cid>=0 else "-"}'
              f'  S:@{hex(idx_s) if idx_s>=0 else "-"}', flush=True)
        if idx_cid >= 0:
            # 从 CID 往前找可能的 proto 起点：假设 CID 前 ≤200 字节内有 proto 起点
            start = max(0, idx_cid - 200)
            proto_zone = data[start:idx_cid + 200]
            zone_name = f'cgi_hunt_{ts_str}_h{p["n"]}_cidzone.bin'
            (OUT_DIR/zone_name).write_bytes(proto_zone)
            print(f'    → CID zone [{hex(start)}..{hex(idx_cid+200)}] → {zone_name}', flush=True)
        return
    if t!='hit': return

    # ★ 关键：一进来先原样落盘 ndjson，避免后续 print/write 被中断丢数据
    with ndjson_p.open('a',encoding='utf-8') as f:
        f.write(json.dumps(p, ensure_ascii=False)+'\n')

    cap=p; hits_all.append(cap)
    N=cap['N']; cands=cap.get('candidates',[])
    esp_hex=cap.get('esp','?'); ebp_hex=cap.get('ebp','?')
    cf_size=cap.get('caller_frame_size',0)
    scan_sum=cap.get('scan_summary',[])
    frames=cap.get('frames',[])

    print(f'\n{"="*76}', flush=True)
    print(f'★ HIT #{cap["n"]}  N={N}  args={cap["args"]}', flush=True)
    print(f'  esp={esp_hex}  ebp={ebp_hex}  caller_frame_size={cf_size}', flush=True)
    print(f'  a2: {cap.get("a2_excerpt","")[:160]}', flush=True)
    if scan_sum:
        print(f'  heap_scan: dword==N 命中 {scan_sum[0].get("total","?")} 处', flush=True)
    if frames:
        print(f'  backtrace ACCURATE:', flush=True)
        for fr in frames[:6]:
            print(f'    #{fr["i"]} {fr["ret"]}  {fr["sym"]}', flush=True)
    print(f'  候选数: {len(cands)}', flush=True)

    for ci,c in enumerate(cands):
        raw_hex=c.get('hex','')
        if not raw_hex: continue
        raw=bytes.fromhex(raw_hex[:N*2])
        fields=pb_decode(raw); score=pb_score(fields)
        has_str=sum(1 for f in fields if f['w']=='str')
        has_cid=fields_contain_cid(fields)

        flag=''
        if has_cid: flag=' ★CID★★★'
        if c.get('looks_pb'): flag+=' pb?'
        if score>=6: flag+=' ✦'

        # 只打印高分或 CID
        if has_cid or score>=6 or c.get('looks_pb'):
            print(f'\n  [{ci}] {c["src"][:60]}  addr={c["addr"]}  score={score}  pb={len(fields)}  str={has_str}{flag}', flush=True)
            if fields and (score>=3 or has_cid):
                print_fields(fields[:12], indent=1)

        # 命中时首次全量落盘
        if has_cid and not found_cid['v']:
            found_cid.update({'v':True, 'src':c['src'], 'hit':cap['n'], 'ci':ci})
            print(f'\n  🎯🎯🎯 找到 CID! src={c["src"]}  addr={c["addr"]}', flush=True)

        bin_name=f'cgi_hunt_{ts_str}_h{cap["n"]}_c{ci}.bin'
        (OUT_DIR/bin_name).write_bytes(raw)

    # ndjson 已在函数开头写过，这里不再重复

    if found_cid['v']:
        print(f'\n[!] 已找到 CID，本轮 P0 达成。等 CAPTURE_SEC 结束以收集更多样本。', flush=True)

print('[*] 获取 PID...', flush=True)
pid=get_pid()
print('[*] Attaching...', flush=True)
sess=frida.get_local_device().attach(pid)
sc=sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(1)

print(f'\n{"="*76}', flush=True)
print(f'★★★ 请在 {CAPTURE_SEC}s 内：', flush=True)
print(f'    1. 在企微 FTA 或其他会话发一条【文字消息】', flush=True)
print(f'    2. 再发一个【小文件】（<1MB 即可）', flush=True)
print(f'    看终端是否出现 ★CID★ / 🎯 标志（成功判据）', flush=True)
print(f'{"="*76}', flush=True)

time.sleep(CAPTURE_SEC)
sc.unload(); sess.detach()

print(f'\n[+] 共 {len(hits_all)} 次命中  ndjson={ndjson_p}', flush=True)
if found_cid['v']:
    print(f'[+] ★ 成功候选：hit#{found_cid["hit"]} c{found_cid["ci"]} src={found_cid["src"]}', flush=True)
else:
    print(f'[-] 未找到 CID。检查 ndjson 里 looks_pb 高分候选，或进入 P0-C（scan "before compress" xref）', flush=True)

# 汇总 summary
summary_p = OUT_DIR / f'cgi_hunt_{ts_str}_summary.json'
summary_p.write_text(json.dumps({
    'hits': len(hits_all),
    'Ns': [h['N'] for h in hits_all],
    'found_cid': found_cid,
    'ndjson': str(ndjson_p),
}, indent=2, ensure_ascii=False), encoding='utf-8')
print(f'[+] summary → {summary_p.name}', flush=True)

os._exit(0)
