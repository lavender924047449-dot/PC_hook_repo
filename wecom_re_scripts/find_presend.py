# find_presend.py — 第三十一轮 P0 · 用看雪字符串反查 xref 定位 PreSendNewMessage / ConstructMessageProtobuf
#
# 参考：https://bbs.kanxue.com/thread-288337-1.htm (私有化版 WeWorkLib.dll 分析)
# 我们的目标：5.0.10.6015 通用版 WXWork.exe 单体
#
# 策略：
#   1. Memory.scanSync WXWork.exe 全模块搜关键字符串（RTTI / log tag / 类名）
#   2. 对每个字符串地址，扫 .text 找 4 字节 LE reference（mov/push imm32）
#   3. 对每个 xref，回退最多 512 字节找函数 prologue (55 8B EC = push ebp; mov ebp, esp)
#   4. 输出函数入口 RVA，方便下一步 Hook

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')

# 关键字符串（按可能性排序）
TARGET_STRINGS = [
    "PreSendNewMessage client_id: ",
    "PreSendNewMessage",
    "weworklocal::logic::PreSendMessageTask2::PreSendNewMessage",
    "ConstructMessageProtobuf",
    "PreSendMessageTask2",
    "weworklocal::logic::PreSendMessageTask2",
    "ProcessForwardMessage",
    # 也搜 wework:: (非 private-deploy 命名空间)
    "wework::logic::PreSendMessageTask2",
    "wework::logic::PreSendMessageTask2::PreSendNewMessage",
    # 通用 CGI/proto builder 相关
    "ChatRequestPackage",
    "SerializeToString",
    "col::ChatRequestPackage",
]

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
send({t:'mod', name: mod.name, base: mod.base.toString(), size: mod.size});

// 找 .text / .rdata 段（PE 头）
function findSections() {
    var pe = mod.base;
    // DOS header @ +0x3c → NT header offset
    var ntOff = pe.add(0x3c).readU32();
    var nt = pe.add(ntOff);
    // NT sig 4 + FileHeader 20 → OptionalHeader; SizeOfOptionalHeader @ FileHeader+16
    var numSec = nt.add(4 + 2).readU16();
    var sizeOfOpt = nt.add(4 + 16).readU16();
    var secHdr = nt.add(4 + 20 + sizeOfOpt);
    var sections = {};
    for (var i = 0; i < numSec; i++) {
        var h = secHdr.add(i * 40);
        // 读 8 字节手动截 null
        var nameBytes = new Uint8Array(h.readByteArray(8));
        var name = '';
        for (var b = 0; b < 8; b++) {
            if (nameBytes[b] === 0) break;
            name += String.fromCharCode(nameBytes[b]);
        }
        var vsize = h.add(8).readU32();
        var vaddr = h.add(12).readU32();
        sections[name] = {base: mod.base.add(vaddr), size: vsize, rva: vaddr};
    }
    return sections;
}

var secs = findSections();
var secList = [];
for (var k in secs) secList.push({name:k, base:secs[k].base.toString(), size:secs[k].size, rva:secs[k].rva});
send({t:'all_sections', sections: secList});

// 兼容命名：.text/CODE/_text ; .rdata/DATA/CONST/_rdata
var textSec = null, rdataSec = null;
var textCandidates = ['.text','CODE','_text','.textbss','text'];
var rdataCandidates = ['.rdata','_rdata','.rodata','CONST','DATA','.data'];
for (var i=0; i<textCandidates.length; i++) if (secs[textCandidates[i]]) { textSec = secs[textCandidates[i]]; break; }
for (var j=0; j<rdataCandidates.length; j++) if (secs[rdataCandidates[j]]) { rdataSec = secs[rdataCandidates[j]]; break; }

// 若都找不到：用可执行权限的最大段作 .text，只读大段作 .rdata
if (!textSec || !rdataSec) {
    // fallback：直接用 Process.enumerateRanges 找模块内部
    var ranges = Process.enumerateRangesSync({protection: 'r-x', coalesce:false});
    var modEnd = mod.base.add(mod.size);
    var textCand = null;
    for (var ri=0; ri<ranges.length; ri++) {
        var rg = ranges[ri];
        if (rg.base.compare(mod.base) >= 0 && rg.base.compare(modEnd) < 0) {
            if (!textCand || rg.size > textCand.size) textCand = rg;
        }
    }
    if (!textSec && textCand) textSec = {base: textCand.base, size: textCand.size, rva: textCand.base.sub(mod.base).toUInt32()};

    var roRanges = Process.enumerateRangesSync({protection: 'r--', coalesce:false});
    var rdCand = null;
    for (var ri2=0; ri2<roRanges.length; ri2++) {
        var rg2 = roRanges[ri2];
        if (rg2.base.compare(mod.base) >= 0 && rg2.base.compare(modEnd) < 0) {
            if (!rdCand || rg2.size > rdCand.size) rdCand = rg2;
        }
    }
    if (!rdataSec && rdCand) rdataSec = {base: rdCand.base, size: rdCand.size, rva: rdCand.base.sub(mod.base).toUInt32()};
}

if (!textSec || !rdataSec) {
    send({t:'err_fatal', e: 'no text/rdata after fallback', have_text: !!textSec, have_rdata: !!rdataSec});
    send({t:'done'});
    throw new Error('abort');
}

// 覆盖 secs 供下面用
secs['.text'] = textSec;
secs['.rdata'] = rdataSec;

send({t:'sections', text: {base: textSec.base.toString(), size: textSec.size, rva: textSec.rva},
                     rdata: {base: rdataSec.base.toString(), size: rdataSec.size, rva: rdataSec.rva}});

// 把字符串转 hex pattern
function strHex(s) {
    var out = '';
    for (var i = 0; i < s.length; i++) {
        out += ('0'+s.charCodeAt(i).toString(16)).slice(-2) + ' ';
    }
    return out.trim();
}

// 4 字节 LE
function dwordHex(v) {
    return ('0'+(v&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>8)&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>16)&0xff).toString(16)).slice(-2)+' '+
           ('0'+((v>>24)&0xff).toString(16)).slice(-2);
}

// 从 xref 位置向前找 prologue (55 8B EC 或 55 89 E5)
function findPrologue(addr, maxBack) {
    var back = maxBack || 0x400;
    for (var i = 0; i < back; i++) {
        try {
            var p = addr.sub(i);
            var b0 = p.readU8(), b1 = p.add(1).readU8(), b2 = p.add(2).readU8();
            // MSVC: push ebp; mov ebp, esp
            if (b0 === 0x55 && b1 === 0x8b && b2 === 0xec) return {addr: p, distance: i};
            // GCC-style: push ebp; mov ebp, esp (Intel syntax alt)
            if (b0 === 0x55 && b1 === 0x89 && b2 === 0xe5) return {addr: p, distance: i};
        } catch(e) { break; }
    }
    return null;
}

// ── 主流程 ────────────────────────────────────────────────────────────
var targets = %TARGETS%;

for (var ti = 0; ti < targets.length; ti++) {
    var s = targets[ti];
    var pat = strHex(s);

    // 1. 在 .rdata 里找字符串
    var strHits = [];
    try {
        strHits = Memory.scanSync(secs['.rdata'].base, secs['.rdata'].size, pat);
    } catch(e) { send({t:'err', s:s, e: String(e)}); continue; }

    if (strHits.length === 0) {
        send({t:'str', s: s, count: 0, hits: [], xrefs: []});
        continue;
    }

    var strAddrs = strHits.map(function(h){ return h.address; });
    var xrefResults = [];

    // 2. 对每个字符串地址，在 .text 里搜 4 字节 LE
    for (var sh = 0; sh < strAddrs.length && sh < 3; sh++) {
        var strAddr = strAddrs[sh];
        var refPat = dwordHex(strAddr.toUInt32());
        var refHits = [];
        try {
            refHits = Memory.scanSync(secs['.text'].base, secs['.text'].size, refPat);
        } catch(e) {}

        // 3. 对每个 xref 找 prologue
        var funcs = [];
        for (var rh = 0; rh < refHits.length && rh < 5; rh++) {
            var xrefAddr = refHits[rh].address;
            var prot = findPrologue(xrefAddr, 0x600);
            var f = {xref: xrefAddr.toString(), xref_rva: '0x'+xrefAddr.sub(mod.base).toString(16)};
            if (prot) {
                f.func = prot.addr.toString();
                f.func_rva = '0x'+prot.addr.sub(mod.base).toString(16);
                f.distance = prot.distance;
            }
            funcs.push(f);
        }

        xrefResults.push({
            str_addr: strAddr.toString(),
            str_rva: '0x'+strAddr.sub(mod.base).toString(16),
            xref_count: refHits.length,
            funcs: funcs
        });
    }

    send({t:'str', s: s, count: strHits.length, str_hits: strAddrs.map(function(a){return a.toString();}).slice(0,5), xrefs: xrefResults});
}

send({t:'done'});
"""

JS = JS.replace('%TARGETS%', json.dumps(TARGET_STRINGS))

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('未找到 :9882 LISTENING')

results = []
mod_info = {}
sections = {}
done = {'v': False}

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:400]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']; t = p.get('t')
    if t == 'mod':
        print(f'[+] Module: {p["name"]} base={p["base"]} size={p["size"]/1024/1024:.1f}MB', flush=True)
        mod_info.update(p); return
    if t == 'all_sections':
        print(f'[+] 全部段（PE header）:', flush=True)
        for s in p['sections']:
            print(f'    {s["name"]:12s} base={s["base"]}  size={s["size"]/1024/1024:>6.1f}MB  rva=0x{s["rva"]:x}', flush=True)
        return
    if t == 'sections':
        print(f'[+] USED .text  base={p["text"]["base"]}  size={p["text"]["size"]/1024/1024:.1f}MB  rva=0x{p["text"]["rva"]:x}', flush=True)
        print(f'[+] USED .rdata base={p["rdata"]["base"]}  size={p["rdata"]["size"]/1024/1024:.1f}MB  rva=0x{p["rdata"]["rva"]:x}', flush=True)
        sections.update(p); return
    if t == 'err_fatal':
        print(f'[FATAL] {p}', flush=True); return
    if t == 'err':
        print(f'[ERR] scanning {p["s"]!r}: {p["e"]}', flush=True); return
    if t == 'done':
        done['v'] = True; return
    if t == 'str':
        results.append(p)
        s = p['s']; cnt = p['count']
        if cnt == 0:
            print(f'\n[-] {s!r}: NOT FOUND in .rdata', flush=True); return

        print(f'\n[+] {s!r}: {cnt} 处 .rdata 命中', flush=True)
        for hi, xr in enumerate(p.get('xrefs', [])):
            print(f'    str[{hi}] @ {xr["str_addr"]}  RVA={xr["str_rva"]}  → {xr["xref_count"]} 处 .text 引用', flush=True)
            for fi, f in enumerate(xr.get('funcs', [])):
                if 'func_rva' in f:
                    print(f'        xref[{fi}] @ {f["xref"]} → 函数入口 {f["func"]}  ★★ RVA={f["func_rva"]}  (回退 {f["distance"]}B)', flush=True)
                else:
                    print(f'        xref[{fi}] @ {f["xref"]}  RVA={f["xref_rva"]}  (未找到 prologue)', flush=True)

print('[*] 获取 PID...', flush=True)
pid = get_pid()
print(f'    PID = {pid}', flush=True)
print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()

import time
# 等 done 或超时
for _ in range(120):
    if done['v']: break
    time.sleep(1)

sc.unload(); sess.detach()

out_p = OUT_DIR / f'find_presend_{ts}.json'
out_p.write_text(json.dumps({
    'ts': ts, 'pid': pid,
    'module': mod_info, 'sections': sections,
    'results': results
}, indent=2, ensure_ascii=False), encoding='utf-8')
print(f'\n[+] 完成 → {out_p.name}', flush=True)

# 汇总: 打印所有找到函数入口的 target
print(f'\n{"="*72}\n★ 汇总（找到函数入口的字符串）:', flush=True)
for r in results:
    hits_with_func = []
    for xr in r.get('xrefs', []):
        for f in xr.get('funcs', []):
            if 'func_rva' in f:
                hits_with_func.append(f['func_rva'])
    if hits_with_func:
        # 去重
        uniq = sorted(set(hits_with_func))
        print(f'  {r["s"]!r}:  {", ".join(uniq)}', flush=True)

os._exit(0)
