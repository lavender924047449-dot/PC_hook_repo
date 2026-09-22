# find_sendmessage_from_appinfo.py — P2 首步 · SendMessage 主函数定位
# ================================================================
#
# 起点（已知事实）：
#   * 每次转发 → wwdb 触发 `REPLACE INTO message_appinfo(msgid,send_time,appinfo) VALUES(?,?,?);`
#     （§32.3 / 第十六轮实测 5/5 转发都命中）
#   * 该 SQL 字面量在 WXWork.exe `.rdata` **只出现 1 次**（§32.3 已验证）
#   * 静态 xref 唯一 → 直接指向 wwdb prepare wrapper 内部；该 wrapper
#     的 caller 就位于 `PostSendMessageTask2` 编译单元
#     （第十三轮 §31.3 __FILE__ 明证：`post_send_message_task2.cpp`）
#
# 本脚本流程（纯 discovery，不 hook）：
#   1. attach WXWork PID
#   2. 扫 `.rdata` 找 SQL 字面量地址（预期恰好 1 处）
#   3. 扫 `.text` 找该地址的 imm32 xref（`push imm32` / `mov reg, imm32`）
#   4. 每个 xref 位置向前扫函数序言 → 得到 wwdb-wrapper 函数入口（预期 1 处）
#   5. 反汇编 wwdb wrapper 首 128 条指令，导出：
#        · 所有 `call rel32` 目标（可能包含 `sqlite3_prepare_v2` / `bindText`
#          / `sqlite3_step` 真身）
#        · `ret` 前的返回值处理
#   6. **backtrace-lite**：扫 `.text` 找所有 `call rel32 == wwdb_wrapper` 的位点
#      → 每个位点向前找 prologue → 得到 wwdb wrapper 的 **上层 caller** 集合
#      → 结合已知类名字符串扫描（§29.5 wework_classes_all.txt）辅助判断哪些
#        caller 属于 `PostSendMessageTask2` / `SendMessageTaskBase` 等类
#
# 输出：
#   runtime/wecom_re/sendmessage_discovery_<TS>.json
#     {
#       "pid":..., "base":...,
#       "sql_addr":..., "wwdb_wrapper_addr":...,
#       "wwdb_call_targets": [...],
#       "wwdb_upper_callers": [{addr, prologue_bytes, disasm_hint}, ...],
#       "candidates": [推荐下一步 hook 的地址]
#     }
#
# CLI:
#   & Python311 runtime/wecom_re/find_sendmessage_from_appinfo.py
#   & Python311 runtime/wecom_re/find_sendmessage_from_appinfo.py --pid 12345
# ================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# SQL 锚点候选（按由强到弱依次尝试；本项目 `.rdata` 常存**短片段**
# 因为编译器可能把 SQL 拆成多段拼接）。第一个命中即用。
# hook_sqlite_bind.py §32 已实测 short pattern 有效。
SQL_ANCHOR_CANDIDATES = [
    # 40 字符短锚点（第十四轮已实证有命中）
    "message_appinfo(msgid,send_time,appinfo)",
    # 更短兜底
    "replace into message_appinfo",
    "message_appinfo(msgid",
    # 极短兜底（可能有较多假阳性，最后才用）
    "message_appinfo",
]
# 兼容旧 CLI --anchor（若传入则仅试这一条）

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const base = wx.base;
const wxEnd = base.add(wx.size);

send({t:'info', base: base.toString(), size: wx.size, name: wx.name});

// ── helpers ────────────────────────────────────────────────────
function scanRdataForBytes(bytesHexPat){
    const ranges = wx.enumerateRanges('r--').concat(wx.enumerateRanges('rw-'));
    const hits = [];
    ranges.forEach(function(r){
        try {
            Memory.scanSync(r.base, r.size, bytesHexPat).forEach(function(h){
                hits.push(h.address);
            });
        } catch(e){}
    });
    return hits;
}

function addrLePattern(addr){
    const v = addr.toUInt32();
    function h(x){ const s = x.toString(16); return s.length < 2 ? '0'+s : s; }
    return h(v & 0xff) + ' ' + h((v>>>8)&0xff) + ' ' + h((v>>>16)&0xff)
           + ' ' + h((v>>>24)&0xff);
}

// 扫可读段找 4 字节小端 imm32 pattern，返回 {code: [], data: []}
// 分类依据：hit 所落的段的 protection 属性
//   'r-x' 段 → code xref（真正的 PUSH/MOV/LEA imm32）
//   'r--' / 'rw-' 段 → data xref（静态数据结构里存着指针）
function findImm32Refs(addr){
    const pat = addrLePattern(addr);
    const code = [], data = [];
    ['r-x', 'r--', 'rw-'].forEach(function(prot){
        wx.enumerateRanges(prot).forEach(function(r){
            try {
                Memory.scanSync(r.base, r.size, pat).forEach(function(h){
                    (prot === 'r-x' ? code : data).push(h.address);
                });
            } catch(e){}
        });
    });
    return {code: code, data: data};
}

// 从 addr 向前 maxBack 字节内查函数序言（55 8B EC / 8B FF 55 8B EC）
function findPrologueBefore(addr, maxBack){
    maxBack = maxBack || 16384;
    let start = addr.sub(maxBack);
    if (start.compare(base) < 0) start = base;
    const size = addr.toUInt32() - start.toUInt32();
    let bytes;
    try { bytes = new Uint8Array(start.readByteArray(size)); }
    catch(e){ return null; }
    for (let i = bytes.length - 5; i >= 0; i--){
        if (bytes[i]===0x8b && bytes[i+1]===0xff && bytes[i+2]===0x55 &&
            bytes[i+3]===0x8b && bytes[i+4]===0xec)
            return start.add(i);
        if (bytes[i]===0x55 && bytes[i+1]===0x8b && bytes[i+2]===0xec)
            return start.add(i);
    }
    return null;
}

// 反汇编 addr 起 nIns 条指令，返回精简结构
function disasmN(addr, nIns){
    const out = [];
    let pc = addr;
    for (let i = 0; i < nIns; i++){
        try {
            const ins = Instruction.parse(pc);
            const row = {
                pc: pc.toString(),
                mnemonic: ins.mnemonic,
                opStr: ins.opStr,
                bytes_hex: null,
            };
            try {
                const sz = ins.size;
                const buf = new Uint8Array(pc.readByteArray(sz));
                let h = ''; for (let j = 0; j < buf.length; j++){
                    const b = buf[j]; if (b < 16) h += '0'; h += b.toString(16);
                }
                row.bytes_hex = h;
            } catch(e){}
            // 直接 call rel32：把目标拆出来
            if (ins.mnemonic === 'call'){
                try {
                    const tgt = ptr(ins.opStr);
                    if (tgt.compare(base) >= 0 && tgt.compare(wxEnd) < 0)
                        row.call_target = tgt.toString();
                } catch(e){}
            }
            out.push(row);
            pc = ins.next;
            if (ins.mnemonic === 'ret') break;
        } catch(e){ break; }
    }
    return out;
}

// 扫 .text 找所有 CALL rel32 == target 的位点
function findCallSitesTo(target){
    const tgtU = target.toUInt32();
    const hits = [];
    wx.enumerateRanges('r-x').forEach(function(r){
        let buf;
        try { buf = new Uint8Array(r.base.readByteArray(r.size)); }
        catch(e){ return; }
        for (let i = 0; i < buf.length - 4; i++){
            if (buf[i] !== 0xe8) continue;
            let rel = buf[i+1] | (buf[i+2]<<8) | (buf[i+3]<<16) | (buf[i+4]<<24);
            if (rel & 0x80000000) rel = rel - 0x100000000;
            const callSite = r.base.toUInt32() + i;
            const callTgt = (callSite + 5 + rel) >>> 0;
            if (callTgt === tgtU) hits.push(ptr(callSite));
        }
    });
    return hits;
}

// 内存里"就近类名"辅助：在 addr 前后 2KB 内扫 "class wework::" 前缀
function nearbyClassName(funcAddr){
    // 一般 vtable / RTTI-lite 类名字符串位于 .rdata；这里只做粗探
    const CAP = 2048;
    let start = funcAddr.sub(CAP), end = funcAddr.add(CAP);
    if (start.compare(base) < 0) start = base;
    if (end.compare(wxEnd) > 0) end = wxEnd;
    try {
        const buf = new Uint8Array(start.readByteArray(
                        end.toUInt32() - start.toUInt32()));
        const needle = 'class wework::';
        for (let i = 0; i < buf.length - needle.length; i++){
            let ok = true;
            for (let j = 0; j < needle.length; j++){
                if (buf[i+j] !== needle.charCodeAt(j)){ ok = false; break; }
            }
            if (ok){
                // read till first \0 (up to 128)
                let s = '';
                for (let k = i; k < Math.min(buf.length, i+128); k++){
                    const c = buf[k];
                    if (c === 0) break;
                    if (c < 32 || c > 126){ s = ''; break; }
                    s += String.fromCharCode(c);
                }
                if (s) return s;
            }
        }
    } catch(e){}
    return null;
}

// ── 主流程 ─────────────────────────────────────────────────────
rpc.exports = {
    discover: function(anchors){
        const out = {sql_addr: null, sql_addr_all: [],
                     sql_anchor_used: null,
                     wwdb_wrapper_addr: null,
                     wwdb_call_targets: [], wwdb_upper_callers: [],
                     candidates: [], notes: []};

        // 依次尝试 anchor 候选，取第一个命中的
        let hits = [];
        let usedAnchor = null;
        for (let ai = 0; ai < anchors.length; ai++){
            const anchor = anchors[ai];
            const pat = Array.from(anchor).map(function(c){
                const h = c.charCodeAt(0).toString(16);
                return h.length < 2 ? '0'+h : h;
            }).join(' ');
            const h = scanRdataForBytes(pat);
            out.notes.push('anchor #' + ai + ' [' + anchor.length +
                           ' chars] → ' + h.length + ' hits');
            if (h.length){ hits = h; usedAnchor = anchor; break; }
        }
        if (!hits.length){
            out.notes.push('ALL anchors missed; try dumping .rdata around ' +
                           '"message_appinfo" region for manual inspection');
            return out;
        }
        out.sql_addr = hits[0].toString();
        out.sql_addr_all = hits.map(function(h){ return h.toString(); });
        out.sql_anchor_used = usedAnchor;

        // xref：对所有 hits 分别扫 code 和 data 段
        const codeSeen = {}, dataSeen = {};
        const codeXrefs = [], dataXrefs = [];
        const xrefByHit = {};
        hits.forEach(function(hitAddr){
            const rs = findImm32Refs(hitAddr);
            xrefByHit[hitAddr.toString()] =
                {code: rs.code.length, data: rs.data.length};
            rs.code.forEach(function(x){
                const k = x.toString();
                if (!codeSeen[k]){ codeSeen[k] = true; codeXrefs.push(x); }
            });
            rs.data.forEach(function(x){
                const k = x.toString();
                if (!dataSeen[k]){ dataSeen[k] = true; dataXrefs.push(x); }
            });
        });
        out.xref_by_hit = xrefByHit;
        out.code_xrefs = codeXrefs.map(function(x){ return x.toString(); });
        out.data_xrefs = dataXrefs.map(function(x){ return x.toString(); });
        out.notes.push('code imm32 xref sites = ' + codeXrefs.length);
        out.notes.push('data imm32 xref sites = ' + dataXrefs.length);

        // ── 二跳：若代码无 xref 但数据段有 → wwdb 通过 static SQL 表引用
        //         那么再扫代码里对**数据 xref 地址本身**的引用（一层间接）
        let xrefs = codeXrefs.slice();
        if (!codeXrefs.length && dataXrefs.length){
            out.notes.push('data-only xref → doing 2-hop scan '
                           + '(scan code for pointers to data-xref sites)');
            const hop2Seen = {};
            dataXrefs.forEach(function(dx){
                // dx 是数据段中 SQL 指针所在的位置
                // 扫代码里对 dx 的 imm32 引用（即 push/mov &table_entry）
                const r2 = findImm32Refs(dx);
                r2.code.forEach(function(x){
                    const k = x.toString();
                    if (!hop2Seen[k]){ hop2Seen[k] = true; xrefs.push(x); }
                });
            });
            out.notes.push('2-hop code xref sites = ' + (xrefs.length));
        }

        if (!xrefs.length){
            out.notes.push('no reachable code xref (1-hop or 2-hop) → '
                           + 'may need Frida runtime hook on the wwdb '
                           + 'prepare_v2 wrapper instead');
            return out;
        }

        // 每个 xref 向前找 prologue → wwdb wrapper 入口
        const wrapperCounter = {};
        xrefs.forEach(function(x){
            const p = findPrologueBefore(x, 16384);
            if (p) wrapperCounter[p.toString()] =
                        (wrapperCounter[p.toString()] || 0) + 1;
        });
        let bestKey = null, bestVote = 0;
        Object.keys(wrapperCounter).forEach(function(k){
            if (wrapperCounter[k] > bestVote){
                bestVote = wrapperCounter[k]; bestKey = k;
            }
        });
        if (!bestKey){
            out.notes.push('wwdb wrapper prologue not resolved');
            return out;
        }
        out.wwdb_wrapper_addr = bestKey;
        // 完整列出所有 wrapper candidates（供人工判断，很可能不止 1 个）
        out.wwdb_wrapper_all = Object.keys(wrapperCounter).map(function(k){
            return {addr: k, votes: wrapperCounter[k]};
        }).sort(function(a,b){ return b.votes - a.votes; });
        out.notes.push('wwdb_wrapper candidates = ' +
                       Object.keys(wrapperCounter).length +
                       ' (top voted=' + bestVote + ')');

        // 反汇编 wwdb wrapper 首 96 条
        const wrapperPtr = ptr(bestKey);
        const disasm = disasmN(wrapperPtr, 96);
        out.wwdb_call_targets = disasm.filter(function(r){
            return r.call_target;
        }).map(function(r){ return r.call_target; });
        out.wwdb_disasm_head = disasm.slice(0, 40);  // 只留前 40 条给 human 看

        // 找 wwdb wrapper 上层 caller
        const callSites = findCallSitesTo(wrapperPtr);
        out.notes.push('wwdb_wrapper call sites = ' + callSites.length);
        const upperFuncs = {};
        callSites.forEach(function(cs){
            const p = findPrologueBefore(cs, 16384);
            if (!p) return;
            const k = p.toString();
            if (!upperFuncs[k]){
                upperFuncs[k] = {addr: k, call_sites: [], class_hint: null};
                upperFuncs[k].class_hint = nearbyClassName(p);
            }
            upperFuncs[k].call_sites.push(cs.toString());
        });
        out.wwdb_upper_callers = Object.keys(upperFuncs).map(function(k){
            return upperFuncs[k];
        });

        // candidates 推荐：class_hint 命中 wework:: 优先，其次 call_sites 少的
        out.candidates = out.wwdb_upper_callers.slice().sort(function(a, b){
            const aClass = a.class_hint ? 1 : 0;
            const bClass = b.class_hint ? 1 : 0;
            if (aClass !== bClass) return bClass - aClass;
            return a.call_sites.length - b.call_sites.length;
        }).slice(0, 5).map(function(x){ return x.addr; });

        return out;
    },
    disasm: function(addr, n){
        return disasmN(ptr(addr), n | 0);
    },
    bye: function(){ send({t:'bye'}); },
};

send({t:'ready'});
"""


def get_wxwork_pid() -> int:
    """通过 :9882 端口锁定主进程。"""
    r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    for line in r.stdout.splitlines():
        if ":9882" in line and "LISTENING" in line:
            parts = line.split()
            return int(parts[-1])
    raise RuntimeError("WXWork.exe :9882 not listening; is 企微 running?")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--anchor", type=str, default=None,
                    help="覆盖默认 anchor 候选列表，只用这一条")
    ap.add_argument("--disasm", type=str, default=None,
                    help="额外反汇编一个地址（会追加到输出），如 0xb59427")
    ap.add_argument("--disasm-n", type=int, default=80)
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID = {pid}")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)

    events: list[dict[str, Any]] = []
    ready = {"v": False}

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "info":
                print(f"[+] wx base={p['base']} size={p['size']}")
            elif p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "bye":
                print("[BYE]")
            else:
                events.append(p)
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    anchors = [args.anchor] if args.anchor else SQL_ANCHOR_CANDIDATES
    print(f"[*] discovery: trying {len(anchors)} SQL anchor candidate(s) ...")
    result = script.exports_sync.discover(anchors)

    if args.disasm:
        print(f"[*] extra disasm at {args.disasm} × {args.disasm_n} ...")
        result["extra_disasm"] = script.exports_sync.disasm(
            args.disasm, args.disasm_n
        )

    result["pid"] = pid
    result["ts"] = ts
    out = OUT_DIR / f"sendmessage_discovery_{ts}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                   encoding="utf-8")

    print("─" * 60)
    print(f"[+] sql_anchor_used    = {result.get('sql_anchor_used')!r}")
    print(f"[+] sql_addr (first)   = {result.get('sql_addr')}")
    all_addrs = result.get("sql_addr_all") or []
    if len(all_addrs) > 1:
        print(f"    (共 {len(all_addrs)} 处 hit：{all_addrs[:5]}"
              f"{' ...' if len(all_addrs) > 5 else ''})")
    print(f"[+] code_xrefs         = {len(result.get('code_xrefs') or [])}")
    print(f"[+] data_xrefs         = {len(result.get('data_xrefs') or [])}")
    for dx in (result.get("data_xrefs") or [])[:6]:
        print(f"      data @ {dx}   (static SQL table entry)")
    print(f"[+] wwdb_wrapper_addr  = {result.get('wwdb_wrapper_addr')} (top)")
    wrappers_all = result.get("wwdb_wrapper_all") or []
    if len(wrappers_all) > 1:
        print(f"    All {len(wrappers_all)} wrapper candidates (addr, votes):")
        for w in wrappers_all[:8]:
            print(f"      {w['addr']}   votes={w['votes']}")
    print(f"[+] wwdb call targets  = {len(result.get('wwdb_call_targets', []))}")
    tgts = result.get("wwdb_call_targets", [])
    for t in tgts[:12]:
        print(f"      call → {t}")
    print(f"[+] upper callers      = {len(result.get('wwdb_upper_callers', []))}")
    for c in result.get("wwdb_upper_callers", [])[:10]:
        hint = c.get("class_hint") or "(no class hint)"
        print(f"      {c['addr']}  sites={len(c['call_sites'])}  {hint}")
    print(f"[+] top candidates     = {result.get('candidates', [])}")
    print(f"[+] notes:")
    for n in result.get("notes", []):
        print(f"      · {n}")
    print(f"[+] → written {out.name}")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
