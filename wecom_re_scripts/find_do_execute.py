# find_do_execute.py — P2 · 定位 PostSendMessageTask2::DoExecute（第二十四轮）
# =============================================================================
#
# 前置发现（第二十四轮 · scan_sendmsg_strings.py）：
#   `0xb52b738`  'PostSendMessageTask2 execte, conversationId = '
#   `0xb52c170`  'PostSendMessageTask2, upload resource conversationId = '
#   `0xb52c610`  'PostSendMessageTask2 SendMessage tmp_task_key is '
#
# 本脚本目标：对日志字符串做 imm32 xref 反查函数入口
#   1. 扫 wxwork.exe `.text` 找 `push imm32` = 68 <addr32> 引用日志字符串
#   2. 扫 `mov reg, imm32` = B8/B9/BA/BB/BE/BF <addr32>
#   3. 每个 xref 向前扫最多 4KB 找函数序言 (55 8B EC / 6A ?? 68)
#   4. 输出候选函数入口，方便下一步 hook
#
# 用法（无需用户操作）：
#   & Python311 runtime/wecom_re/find_do_execute.py
# =============================================================================

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

# 待反查的字符串 VA（wxwork.exe 载入 base=0x970000 时的绝对地址）
LOG_STRING_VAS = [
    ("0xb52b738", "PostSendMessageTask2 execte, conversationId = "),
    ("0xb52c170", "PostSendMessageTask2, upload resource conversationId = "),
    ("0xb52c610", "PostSendMessageTask2 SendMessage tmp_task_key is "),
    ("0xb52b697", "PostSendMessageTask2 filled conv_msgs count: "),
    ("0xb52b8c5", "PostSendMessageTask2::DoExecute] retry init security sdk"),
    ("0xb52b901", "PostSendMessageTask2::DoExecute] retry init e2e security manager"),
    ("0xb52b9bc", "PostSendMessageTask2, need upload resource conversationId = "),
]

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const BASE = wx.base.toUInt32();
const SIZE = wx.size;
const END = BASE + SIZE;
send({t:'info', msg: 'wx base=0x' + BASE.toString(16) + ' size=0x' + SIZE.toString(16)});

// 判断某地址是否可读、可执行
function isTextAddr(addr){
    try {
        const r = Process.findRangeByAddress(ptr(addr));
        return r && r.protection.indexOf('r') >= 0;
    } catch(e){ return false; }
}

// 把 32-bit VA 写成 4 个 LE bytes 的 hex pattern
function vaToBytes(va){
    const a = (va >>> 0) & 0xff;
    const b = (va >>> 8) & 0xff;
    const c = (va >>> 16) & 0xff;
    const d = (va >>> 24) & 0xff;
    function h(x){ return x.toString(16).padStart(2, '0'); }
    return h(a) + ' ' + h(b) + ' ' + h(c) + ' ' + h(d);
}

// 扫 wxwork.exe 内所有段找 32-bit imm 引用（push imm32 / mov reg, imm32）
function scanXref(targetVa){
    const pattern = vaToBytes(targetVa);
    const results = [];
    try {
        // 只扫可读段（去掉 execute-only）
        const ranges = Process.enumerateRanges({protection: 'r--', coalesce: false})
                       .concat(Process.enumerateRanges({protection: 'r-x', coalesce: false}))
                       .concat(Process.enumerateRanges({protection: 'rw-', coalesce: false}));
        // 过滤到 wxwork.exe 内
        const wxRanges = ranges.filter(function(rr){
            const b = rr.base.toUInt32();
            return b >= BASE && b < END;
        });
        // 去重（enumerateRanges 有时重复）
        const seen = {};
        for (let i = 0; i < wxRanges.length; i++){
            const rr = wxRanges[i];
            const key = rr.base.toString();
            if (seen[key]) continue;
            seen[key] = true;
            try {
                const ms = Memory.scanSync(rr.base, rr.size, pattern);
                for (let j = 0; j < ms.length; j++){
                    const a = ms[j].address.toUInt32();
                    // 前 1 字节看是 push imm32 (0x68) 还是 mov reg, imm32 (0xB8-0xBF)
                    let leadByte = 0;
                    try { leadByte = ms[j].address.sub(1).readU8(); } catch(e){}
                    let kind = 'raw';
                    if (leadByte === 0x68) kind = 'push';
                    else if (leadByte >= 0xB8 && leadByte <= 0xBF) kind = 'mov_' + (leadByte - 0xB8);
                    results.push({
                        at: '0x' + a.toString(16),
                        prot: rr.protection,
                        kind: kind,
                        lead: '0x' + leadByte.toString(16)
                    });
                }
            } catch(e){}
        }
    } catch(e){
        send({t:'error', msg: 'scan(' + targetVa.toString(16) + ') failed: ' + e.message});
    }
    return results;
}

// 向前扫函数序言 (55 8B EC / 6A ?? 8B FF 55 8B EC / 8B FF 55 8B EC)
// 从 xref_at - 1 开始向前扫最多 8KB
function findPrologueBefore(refAt, maxScan){
    const MAX = maxScan || 8192;
    for (let off = 4; off < MAX; off++){
        const p = refAt - off;
        if (p < BASE) break;
        let b0 = 0, b1 = 0, b2 = 0;
        try {
            b0 = ptr(p).readU8();
            b1 = ptr(p + 1).readU8();
            b2 = ptr(p + 2).readU8();
        } catch(e){ continue; }
        // 55 8B EC  = push ebp; mov ebp, esp
        if (b0 === 0x55 && b1 === 0x8B && b2 === 0xEC) return p;
        // 8B FF 55 8B EC = mov edi, edi; push ebp; mov ebp, esp (hotpatch)
        try {
            const b_1 = ptr(p - 2).readU8();
            const b_0 = ptr(p - 1).readU8();
            if (b_1 === 0x8B && b_0 === 0xFF && b0 === 0x55 && b1 === 0x8B && b2 === 0xEC){
                return p - 2;
            }
        } catch(e){}
    }
    return 0;
}

rpc.exports = {
    findXrefs: function(vas){
        const out = [];
        for (let i = 0; i < vas.length; i++){
            const va = parseInt(vas[i], 16);
            const xs = scanXref(va);
            const withPrologue = [];
            for (let j = 0; j < xs.length; j++){
                const x = xs[j];
                const at = parseInt(x.at, 16);
                if (x.kind === 'push' || x.kind.indexOf('mov_') === 0){
                    const p = findPrologueBefore(at, 16384);
                    x.prologue = p ? ('0x' + p.toString(16)) : null;
                    x.offset_from_prologue = p ? (at - p) : null;
                }
                withPrologue.push(x);
            }
            send({t:'progress', va: '0x' + va.toString(16), hits: withPrologue.length});
            out.push({va: '0x' + va.toString(16), xrefs: withPrologue});
        }
        return out;
    }
};
send({t:'ready'});
"""


def get_wxwork_pid() -> int:
    r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    for line in r.stdout.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.split()[-1])
    raise RuntimeError("WXWork.exe :9882 not listening")


def main() -> int:
    pid = get_wxwork_pid()
    print(f"[*] attaching PID={pid}")

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                print(f"[+] {p['msg']}")
            elif t == "progress":
                print(f"    - anchor {p['va']}  → {p['hits']} xref(s)")
            elif t == "error":
                print(f"[!] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    print("[*] scanning xrefs...")
    t0 = time.monotonic()
    results = script.exports_sync.find_xrefs([va for va, _label in LOG_STRING_VAS])
    print(f"[+] xref scan done in {time.monotonic()-t0:.1f}s")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUT_DIR / f"do_execute_xrefs_{ts}.json"
    out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] → {out_path.name}")

    print()
    print("=" * 80)
    prologue_ctr: Counter[str] = Counter()
    for r in results:
        va = r["va"]
        label = next((lbl for v, lbl in LOG_STRING_VAS if v == va), "?")
        print(f"\n[anchor] {va}  '{label}'")
        for x in r["xrefs"]:
            prol = x.get("prologue") or "N/A"
            off = x.get("offset_from_prologue")
            print(f"  ref @ {x['at']:12s}  kind={x['kind']:8s}  prot={x['prot']}  "
                  f"prologue={prol}  off_from_prol={off}")
            if x.get("prologue"):
                prologue_ctr[x["prologue"]] += 1

    print("\n" + "=" * 80)
    print("Top prologue candidates (投票 top 20，出现在多个日志字符串附近的函数最可能是 DoExecute)：")
    for prol, n in prologue_ctr.most_common(20):
        print(f"  {prol:12s}  count={n}")

    summary_path = OUT_DIR / f"do_execute_xrefs_{ts}_summary.json"
    summary_path.write_text(json.dumps({
        "top_prologues": prologue_ctr.most_common(30),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] → {summary_path.name}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
