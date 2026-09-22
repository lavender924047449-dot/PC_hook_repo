# hunt_task_ctor.py — P2 · 定位 PostSendMessageTask2 构造函数入口（第二十三轮）
# =============================================================================
#
# 前置发现（第二十二轮）：
#   `0x8d59e82` / `0x8dd8202` 都在**已序列化后层次** —— payload buffer 已经
#   在 task 对象里，与 conv_id 独立参数无关。整条 wwdb → task queue 链路都
#   在 SendMessageTask 序列化之后。
#
# 本脚本目标：跨线程回溯 —— 拿到"谁分配了这个 payload buffer"。
#
# 原理：
#   1. hook `RtlAllocateHeap` (ntdll)，onLeave 记录 (size, retval, tid,
#      return_addr) 到轻量 ring buffer（size in [256, 16384]）
#   2. hook `0x8dd8202` onEnter，扫 buffer 候选位置找含 S:xxx_yyy 的 payload
#   3. 反查 ring buffer 找匹配的分配 → return_addr 就是构造函数候选
#
# 用户配合：90 秒窗口内做 2-3 次 FTA→外部联系人 转发
# 用法：& Python311 runtime/wecom_re/hunt_task_ctor.py --duration 90
# =============================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_TARGET = "0x8dd8202"

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
send({t:'info', base: wx.base.toString()});

// ---- Ring buffer (JS array — 简单可靠) ----
const RB_CAP = 16384;
let rb = new Array(RB_CAP);
for (let i = 0; i < RB_CAP; i++) rb[i] = null;
let rb_pos = 0;

const SZ_MIN = 128;
const SZ_MAX = 32768;

function u32(np){
    // 兼容不同 Frida 版本
    if (!np) return 0;
    try { return np.toUInt32(); } catch(e){}
    try { return parseInt(np.toString(), 16); } catch(e){}
    return 0;
}

// 优先 RtlAllocateHeap；fallback 到 HeapAlloc（枚举模块 export 查找，兼容 Frida 17）
function resolveExport(modNames, expName){
    for (let mi = 0; mi < modNames.length; mi++){
        const mn = modNames[mi];
        // 方法 1: Module.findExportByName (老 API)
        try {
            if (typeof Module !== 'undefined' && Module.findExportByName){
                const p = Module.findExportByName(mn, expName);
                if (p && !p.isNull()) return {addr: p, mod: mn};
            }
        } catch(e){}
        // 方法 2: Module.getExportByName + Module.load / findBaseAddress
        try {
            if (typeof Module !== 'undefined' && Module.getExportByName){
                const p = Module.getExportByName(mn, expName);
                if (p && !p.isNull()) return {addr: p, mod: mn};
            }
        } catch(e){}
    }
    // 方法 3: 枚举模块 → 枚举 exports
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++){
        const mnl = mods[i].name.toLowerCase();
        let match = false;
        for (let j = 0; j < modNames.length; j++){
            if (mnl === modNames[j].toLowerCase()) { match = true; break; }
        }
        if (!match) continue;
        try {
            const exps = mods[i].enumerateExports();
            for (let k = 0; k < exps.length; k++){
                if (exps[k].name === expName) return {addr: exps[k].address, mod: mods[i].name};
            }
        } catch(e){}
    }
    return null;
}

const resolved = resolveExport(['ntdll.dll', 'kernel32.dll', 'kernelbase.dll'],
                                'RtlAllocateHeap') ||
                 resolveExport(['kernel32.dll', 'kernelbase.dll', 'ntdll.dll'],
                                'HeapAlloc');
if (!resolved) throw new Error('neither RtlAllocateHeap nor HeapAlloc found');
const AllocAddr = resolved.addr;
send({t:'info', msg: 'alloc-hook @ ' + AllocAddr.toString() + ' (' + resolved.mod + ')'});

// stdcall 32-bit signature 相同：(HANDLE, Flags, Size) → PVOID
Interceptor.attach(AllocAddr, {
    onEnter: function(args) {
        try { this._sz = args[2].toInt32(); } catch(e){ this._sz = 0; }
    },
    onLeave: function(retval) {
        const sz = this._sz;
        if (sz < SZ_MIN || sz > SZ_MAX) return;
        const rv = u32(retval);
        if (rv === 0) return;
        let caller = 0;
        try { caller = u32(this.returnAddress); } catch(e){}
        rb[rb_pos % RB_CAP] = {
            size: sz,
            retval: rv,
            tid: Process.getCurrentThreadId(),
            caller: caller,
            when: Date.now()
        };
        rb_pos++;
    }
});
send({t:'info', msg: 'alloc-hook armed'});

let COUNT = 0;

function scanForConvId(bufPtr){
    let bytes = null;
    try { bytes = new Uint8Array(bufPtr.readByteArray(4096)); }
    catch(e) { return null; }
    if (!bytes) return null;
    let s = '';
    for (let i = 0; i < bytes.length; i++){
        const b = bytes[i];
        s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '\x01';
    }
    const m = /(S:\d{10,20}_\d{10,20}|R:[\w:_-]{10,64}|G:[\w:_-]{10,64})/.exec(s);
    return m ? {conv: m[0], at: m.index} : null;
}

function lookupAllocs(bufAddr){
    const SLACK = 128;
    const hits = [];
    for (let i = 0; i < RB_CAP; i++){
        const rec = rb[i];
        if (!rec) continue;
        const diff = bufAddr - rec.retval;
        if (diff >= 0 && diff <= SLACK){
            hits.push({
                retval: '0x' + rec.retval.toString(16),
                size: rec.size,
                tid: rec.tid,
                caller: '0x' + rec.caller.toString(16),
                offset: diff,
                age_ms: Date.now() - rec.when
            });
        }
    }
    // 按 age_ms 升序（最近的分配最可能是 payload buffer）
    hits.sort(function(a, b){ return a.age_ms - b.age_ms; });
    return hits;
}

rpc.exports = {
    install: function(addrStr){
        const t = ptr(addrStr);
        Interceptor.attach(t, {
            onEnter: function(){
                const ecx = this.context.ecx;
                const esp = this.context.esp;
                const cands = [];
                function tryRead(loc, ptrExpr){
                    try {
                        const v = ptrExpr.readU32();
                        if (v && v >= 0x10000) cands.push({loc: loc, addr: v});
                    } catch(e){}
                }
                tryRead('ecx+0x64', ecx.add(0x64));
                tryRead('ecx+0x6c', ecx.add(0x6c));
                tryRead('esp+0x24', esp.add(0x24));
                tryRead('esp+0x28', esp.add(0x28));

                for (let ci = 0; ci < cands.length; ci++){
                    const c = cands[ci];
                    const conv = scanForConvId(ptr(c.addr));
                    if (!conv) continue;
                    const allocs = lookupAllocs(c.addr);
                    COUNT++;
                    send({t:'hit',
                          seq: COUNT,
                          addr: addrStr,
                          this_addr: ecx.toString(),
                          esp: esp.toString(),
                          buf_loc: c.loc,
                          buf_addr: '0x' + c.addr.toString(16),
                          conv_id: conv.conv,
                          conv_at: conv.at,
                          tid: Process.getCurrentThreadId(),
                          allocs: allocs,
                          alloc_count: allocs.length});
                }
            }
        });
        send({t:'installed', addr: addrStr});
    },
    stats: function(){
        return {count: COUNT, rb_pos: rb_pos};
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


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=str, default=DEFAULT_TARGET)
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=90)
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID={pid}, target={args.target}")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"hunt_ctor_{ts}.ndjson"

    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    hits: list[dict[str, Any]] = []
    ready = {"v": False}
    fp = ndjson_path.open("a", encoding="utf-8")

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                if p.get("base"):
                    print(f"[+] wx base = {p['base']}")
                elif p.get("msg"):
                    print(f"[+] {p['msg']}")
            elif t == "installed":
                print(f"[+] hook installed @ {p['addr']}")
            elif t == "hit":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n")
                fp.flush()
                print(f"\n[HIT #{p['seq']}] {p['buf_loc']} → buf={p['buf_addr']}  "
                      f"conv={p['conv_id']!r}  tid={p['tid']}")
                if p['alloc_count']:
                    print(f"  ★ 匹配到 {p['alloc_count']} 条 alloc 记录:")
                    for a in p['allocs'][:5]:
                        print(f"    caller={a['caller']:12s}  size={a['size']:5d}  "
                              f"tid={a['tid']:5d}  off={a['offset']}  age={a['age_ms']}ms")
                    if len(p['allocs']) > 5:
                        print(f"    ... 另 {len(p['allocs']) - 5} 条")
                else:
                    print(f"  ❌ 无 alloc 匹配（buffer 可能通过 pool/arena 分配）")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")
            stk = msg.get("stack")
            if stk: print(f"    stack: {stk[:500]}")

    script.on("message", on_message)
    script.load()
    for _ in range(40):
        if ready["v"]: break
        time.sleep(0.1)
    if not ready["v"]:
        print("[!] JS ready 信号未收到，脚本可能已挂")
        return 1
    script.exports_sync.install(args.target)
    print(f"\n[*] armed for {args.duration}s. 现在做 2-3 次 FTA→外部联系人 转发\n")

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        time.sleep(1)

    fp.close()

    caller_ctr: Counter[str] = Counter()
    tid_ctr: Counter[int] = Counter()
    size_ctr: Counter[int] = Counter()
    for h in hits:
        for a in h.get("allocs", []):
            caller_ctr[a["caller"]] += 1
            tid_ctr[a["tid"]] += 1
            size_ctr[a["size"]] += 1

    print()
    st = script.exports_sync.stats()
    print(f"[+] final: {len(hits)} hits, ring_buffer accum = {st['rb_pos']}")
    print(f"[+] top alloc caller (return address):")
    for caller, n in caller_ctr.most_common(15):
        print(f"    {caller:12s}  count={n}")
    print(f"[+] top tid:")
    for tid, n in tid_ctr.most_common(5):
        print(f"    tid={tid:5d}  count={n}")
    print(f"[+] top size:")
    for sz, n in size_ctr.most_common(5):
        print(f"    size={sz:5d}  count={n}")
    print(f"[+] → {ndjson_path.name}")

    summary_path = OUT_DIR / f"hunt_ctor_{ts}_summary.json"
    summary_path.write_text(json.dumps({
        "hits": len(hits),
        "top_callers": caller_ctr.most_common(30),
        "top_tids": tid_ctr.most_common(10),
        "top_sizes": size_ctr.most_common(10),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] → {summary_path.name}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
