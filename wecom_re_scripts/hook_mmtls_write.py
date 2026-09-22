# hook_mmtls_write.py
# 搜索 WXWork.exe 内 "WriteRecord"/"write_record" 字符串的 PUSH xref，
# 找到 mmtls 明文写入函数，再 hook 它在 TLS 加密前截获 CGI payload
#
# 执行：请在 60s 内多次转发消息
#   & 'C:\Users\LENOVO\AppData\Local\Programs\Python\Python311\python.exe' ^
#     runtime/wecom_re/hook_mmtls_write.py

import frida, subprocess, time, json, sys, os, threading
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CAPTURE_SEC = 60
MAX_PAYLOADS = 500

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID = {pid}', flush=True)

JS = r"""
'use strict';
var wxBase = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
}).base;
var wxSize = Process.getModuleByName('WXWork.exe').size;

// ── 1. 找 "WriteRecord" 字符串的代码 xref ──────────────────────────────────────
// 字符串 RVA: WriteRecord=0x0b862c22, write_record=0x0b87f8bc
var strRVAs = [0x0b862c22, 0x0b87f8bc];
var xrefs = [];
for (var si = 0; si < strRVAs.length; si++) {
    var strAbs = wxBase.add(strRVAs[si]).toUInt32();
    var lo = strAbs & 0xFF;
    var b1 = (strAbs >> 8) & 0xFF;
    var b2 = (strAbs >> 16) & 0xFF;
    var b3 = (strAbs >> 24) & 0xFF;
    // 搜索 MOV/LEA+imm32, PUSH imm32
    var patterns = [
        '68 ' + ('0'+lo.toString(16)).slice(-2) + ' ' +
                ('0'+b1.toString(16)).slice(-2) + ' ' +
                ('0'+b2.toString(16)).slice(-2) + ' ' +
                ('0'+b3.toString(16)).slice(-2),
        'b8 ' + ('0'+lo.toString(16)).slice(-2) + ' ' +
                ('0'+b1.toString(16)).slice(-2) + ' ' +
                ('0'+b2.toString(16)).slice(-2) + ' ' +
                ('0'+b3.toString(16)).slice(-2),
    ];
    for (var pi = 0; pi < patterns.length; pi++) {
        try {
            var res = Memory.scanSync(wxBase, wxSize, patterns[pi]);
            for (var ri = 0; ri < Math.min(res.length, 3); ri++) {
                xrefs.push({
                    strRVA: strRVAs[si],
                    codeRVA: res[ri].address.sub(wxBase).toUInt32(),
                    abs: res[ri].address.toString(),
                    pat: patterns[pi].substring(0, 5)
                });
            }
        } catch(e) {}
    }
}

// ── 2. 对找到的代码 RVA 向前扫描找函数入口 ────────────────────────────────────
function findPrologue(codeAddr, maxBack) {
    for (var off = 1; off < maxBack; off++) {
        var p = codeAddr.sub(off);
        try {
            if (p.readU8() === 0x55 && p.add(1).readU8() === 0x8b && p.add(2).readU8() === 0xec) {
                return {rva: p.sub(wxBase).toUInt32(), abs: p.toString(), offset: off};
            }
        } catch(e) {}
    }
    return null;
}

var fnCandidates = [];
for (var xi = 0; xi < xrefs.length; xi++) {
    var codePtr = ptr(xrefs[xi].abs);
    var prol = findPrologue(codePtr, 2048);
    if (prol) {
        fnCandidates.push({
            strRVA: xrefs[xi].strRVA,
            codeRVA: xrefs[xi].codeRVA,
            fnRVA: prol.rva,
            fnAbs: prol.abs,
            backOffset: prol.offset
        });
    }
}

// ── 3. Hook 找到的函数，抓取明文 ─────────────────────────────────────────────
var hooked = {};
var captures = [];
var totalHit = 0;
var MAX_CAP = 500;

function hookFn(fnAbsStr, fnRVA) {
    if (hooked[fnAbsStr]) return;
    hooked[fnAbsStr] = true;
    try {
        Interceptor.attach(ptr(fnAbsStr), {
            onEnter: function(args) {
                totalHit++;
                if (captures.length >= MAX_CAP) return;
                // 尝试读取 args[0] 到 args[3] 的内容（可能含明文 buffer）
                var rec = {ts: Date.now(), fnRVA: fnRVA, args: []};
                for (var ai = 0; ai < 4; ai++) {
                    var val = args[ai].toUInt32();
                    var hex = '';
                    if (val > 0x10000 && val < 0x80000000) {
                        try {
                            var b = args[ai].readByteArray(Math.min(128, val < 0x10000 ? 128 : 128));
                            hex = Array.from(new Uint8Array(b)).map(function(x){
                                return ('0'+x.toString(16)).slice(-2);
                            }).join(' ');
                        } catch(e) { hex = 'ERR'; }
                    } else {
                        hex = 'INT:' + val.toString();
                    }
                    rec.args.push(hex);
                }
                captures.push(rec);
                send({t:'hit', idx: captures.length, fnRVA: fnRVA});
            }
        });
        send({t:'hooked', fnRVA: fnRVA, fnAbs: fnAbsStr});
    } catch(e) {
        send({t:'hookErr', fnRVA: fnRVA, err: e.message});
    }
}

for (var ci = 0; ci < fnCandidates.length; ci++) {
    hookFn(fnCandidates[ci].fnAbs, fnCandidates[ci].fnRVA);
}

recv('dump', function(_) {
    send({t:'dump_result', captures: captures, totalHit: totalHit});
});

send({t:'ready', xrefs: xrefs, candidates: fnCandidates, wxBase: wxBase.toString()});
"""

all_captures = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[Frida ERR] {msg.get("description","")}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t', '')
    if t == 'ready':
        print(f'[+] wxBase={p.get("wxBase")}', flush=True)
        print(f'[+] xrefs 找到: {len(p.get("xrefs", []))}', flush=True)
        for x in p.get('xrefs', []):
            print(f'    strRVA=0x{x["strRVA"]:08x}  codeRVA=0x{x["codeRVA"]:08x}', flush=True)
        print(f'[+] 函数候选: {len(p.get("candidates", []))}', flush=True)
        for c in p.get('candidates', []):
            print(f'    fnRVA=0x{c["fnRVA"]:08x}  fnAbs={c["fnAbs"]}  back={c["backOffset"]}', flush=True)
    elif t == 'hooked':
        print(f'[+] Hooked fnRVA=0x{p.get("fnRVA"):08x}  @ {p.get("fnAbs")}', flush=True)
    elif t == 'hookErr':
        print(f'[!] HookErr fnRVA=0x{p.get("fnRVA"):08x}: {p.get("err")}', flush=True)
    elif t == 'hit':
        if p.get('idx', 0) % 20 == 1:
            print(f'  [HIT #{p.get("idx")}] fnRVA=0x{p.get("fnRVA"):08x}', flush=True)
    elif t == 'dump_result':
        all_captures.extend(p.get('captures', []))
        print(f'[+] Dump: {len(all_captures)} 条, totalHit={p.get("totalHit")}', flush=True)
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print(f'\n{"="*60}', flush=True)
print(f'★★★ 请在企微多次转发消息 ★★★  ({CAPTURE_SEC}s 窗口)', flush=True)
print(f'{"="*60}\n', flush=True)

time.sleep(CAPTURE_SEC)
print('[*] 正在 dump...', flush=True)
sc.post({'type': 'dump'})
dump_event.wait(timeout=10)

# 分析
print(f'\n{"="*60}', flush=True)
print('[=== 明文内容分析 ===]', flush=True)
for i, cap in enumerate(all_captures[:30]):
    for ai, hexdata in enumerate(cap.get('args', [])):
        if hexdata.startswith('INT:') or hexdata == 'ERR':
            continue
        try:
            bs = bytes.fromhex(hexdata.replace(' ', ''))
            s8 = bs.decode('utf-8', errors='ignore')
            readable = ''.join(c for c in s8 if c.isprintable())
            if len(readable) > 6:
                print(f'  cap[{i}] fnRVA=0x{cap["fnRVA"]:08x} arg[{ai}]: {readable[:100]!r}', flush=True)
        except: pass

# 保存
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'mmtls_write_{ts_str}.json'
out_path.write_text(json.dumps(all_captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out_path}', flush=True)

os._exit(0)
