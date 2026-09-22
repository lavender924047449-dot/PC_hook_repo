# hook_appinfo_candidates.py — P2 · 一体化：discovery + 多点 hook + 定位真身
# ================================================================
#
# 第十八轮（重写版）·企微重启后重跑无需任何缓存文件
#
# 起因：
#   * `hook_wwdb_wrapper_bt.py` hook §32.2 的 `0xb59427` 后证伪—— 它是
#     conversation 相关 wwdb query（GetConversations 等），跟 message_appinfo
#     INSERT 无关（sql_probe 显示的是完全不同的 SQL 表）
#   * `find_sendmessage_from_appinfo.py` 二跳发现 16 个"直接访问 SQL 静态
#     表 entry"的函数候选（每次企微重启地址变化）
#   * 真正处理 message_appinfo 的应在这 16 个里的某 1-2 个
#
# 本脚本单次运行做完 3 件事：
#   [1] discovery：扫 `.rdata` 找 "message_appinfo"（多级 anchor 兜底），
#       对 hit 做 imm32 xref 分 code/data → 若只有 data xref 则做二跳
#       （扫代码对 data-xref 地址的引用），得到 N 个候选函数入口
#   [2] hook all：批量 Interceptor.attach，onEnter 读栈找 cstr；
#       只有栈上任一 cstr 含 `--filter` 的命中才计 match（避免刷屏）
#   [3] hunt：用户转发 1-3 次；每 10s 打印各地址 `match/total`；
#       结束时按 match 降序输出，标记 ★ WINNER
#
# 输出：
#   runtime/wecom_re/appinfo_hunter_<TS>.ndjson
#   runtime/wecom_re/appinfo_hunter_summary_<TS>.json
#     summary 里会同时记录 base + RVA，便于交叉验证 / 未来重用
#
# CLI:
#   & Python311 runtime/wecom_re/hook_appinfo_candidates.py
#   & Python311 runtime/wecom_re/hook_appinfo_candidates.py --duration 240
#   & Python311 runtime/wecom_re/hook_appinfo_candidates.py \
#       --filter "insert into message_table"   # 换个 SQL 定位其它 INSERT
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

# SQL anchor 递降候选（第一个命中即用）
SQL_ANCHOR_CANDIDATES = [
    "message_appinfo(msgid,send_time,appinfo)",  # 40 chars（第十四轮命中过）
    "replace into message_appinfo",              # 28 chars
    "message_appinfo(msgid",                     # 21 chars
    "message_appinfo",                           # 15 chars（第十八轮命中）
]


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
function scanBytesInProt(bytesHexPat, prots){
    const hits = [];
    prots.forEach(function(prot){
        wx.enumerateRanges(prot).forEach(function(r){
            try {
                Memory.scanSync(r.base, r.size, bytesHexPat).forEach(function(h){
                    hits.push(h.address);
                });
            } catch(e){}
        });
    });
    return hits;
}

function scanRdata(bytesHexPat){
    return scanBytesInProt(bytesHexPat, ['r--', 'rw-']);
}

function strToHexPat(s){
    return Array.from(s).map(function(c){
        const h = c.charCodeAt(0).toString(16);
        return h.length < 2 ? '0'+h : h;
    }).join(' ');
}

function addrLePattern(addr){
    const v = addr.toUInt32();
    function h(x){ const s = x.toString(16); return s.length < 2 ? '0'+s : s; }
    return h(v & 0xff) + ' ' + h((v>>>8)&0xff) + ' ' + h((v>>>16)&0xff)
           + ' ' + h((v>>>24)&0xff);
}

// 找所有可读段里 imm32 pattern，分类为 code / data
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

function nearbyClassName(funcAddr, capRadius){
    capRadius = capRadius || 8192;
    let start = funcAddr.sub(capRadius), end = funcAddr.add(capRadius);
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

function readSql(p, cap){
    cap = cap || 512;
    try { return p.readCString(cap); } catch(e){}
    return null;
}

// ── 模块级 hook 状态（保证 rpc.exports 跨调用共享）──────────
let STATS = {};       // {addr_str: {total, match}}
let ORDER = [];       // Insertion order
let SQL_FILTER = null;
// 低频兜底：某地址若总调用数 ≤ LOW_FREQ_THRESH，视为 "跟用户操作强相关"
// 无论 SQL filter 是否命中都强制上报 backtrace（因为它们的 SQL 常内联加载
// `mov reg, offset TABLE_ENTRY`，栈上抓不到 SQL 明文）
const LOW_FREQ_THRESH = 20;

// ── 阶段 1：discovery ─────────────────────────────────────────
rpc.exports = {
    discover: function(anchors){
        const out = {sql_anchor_used: null, sql_addrs: [],
                     code_xrefs: [], data_xrefs: [],
                     hop2_code_xrefs: [],
                     candidates: [], notes: []};
        let hits = [], used = null;
        for (let ai = 0; ai < anchors.length; ai++){
            const pat = strToHexPat(anchors[ai]);
            const h = scanRdata(pat);
            out.notes.push('anchor #' + ai + ' [' + anchors[ai].length +
                           ' chars] → ' + h.length + ' hits');
            if (h.length){ hits = h; used = anchors[ai]; break; }
        }
        if (!hits.length){
            out.notes.push('ALL anchors missed');
            return out;
        }
        out.sql_anchor_used = used;
        out.sql_addrs = hits.map(function(h){ return h.toString(); });

        // 1-hop xrefs
        const codeSeen = {}, dataSeen = {};
        const codeXrefs = [], dataXrefs = [];
        hits.forEach(function(ha){
            const rs = findImm32Refs(ha);
            rs.code.forEach(function(x){
                const k = x.toString();
                if (!codeSeen[k]){ codeSeen[k] = true; codeXrefs.push(x); }
            });
            rs.data.forEach(function(x){
                const k = x.toString();
                if (!dataSeen[k]){ dataSeen[k] = true; dataXrefs.push(x); }
            });
        });
        out.code_xrefs = codeXrefs.map(function(x){ return x.toString(); });
        out.data_xrefs = dataXrefs.map(function(x){ return x.toString(); });
        out.notes.push('1-hop code xrefs = ' + codeXrefs.length);
        out.notes.push('1-hop data xrefs = ' + dataXrefs.length);

        // 2-hop（若 code=0）
        let xrefs = codeXrefs.slice();
        if (!codeXrefs.length && dataXrefs.length){
            const hopSeen = {};
            dataXrefs.forEach(function(dx){
                findImm32Refs(dx).code.forEach(function(x){
                    const k = x.toString();
                    if (!hopSeen[k]){ hopSeen[k] = true; xrefs.push(x); }
                });
            });
            out.hop2_code_xrefs = xrefs.map(function(x){ return x.toString(); });
            out.notes.push('2-hop code xrefs = ' + xrefs.length);
        }

        // 每个 xref 向前找 prologue，去重后按投票排序
        const funcVote = {};
        xrefs.forEach(function(x){
            const p = findPrologueBefore(x, 16384);
            if (!p) return;
            const k = p.toString();
            if (!funcVote[k]) funcVote[k] = 0;
            funcVote[k]++;
        });
        out.candidates = Object.keys(funcVote).sort(function(a, b){
            return funcVote[b] - funcVote[a];
        }).map(function(k){
            return {
                addr: k,
                votes: funcVote[k],
                class_hint: nearbyClassName(ptr(k)),
            };
        });
        out.notes.push('candidate funcs = ' + out.candidates.length);
        return out;
    },

    // ── 阶段 2：批量 hook ─────────────────────────────────────
    install: function(addrList, sqlFilter){
        STATS = {};
        ORDER = addrList.slice();
        SQL_FILTER = (sqlFilter && sqlFilter.length) ? sqlFilter : null;

        addrList.forEach(function(a){
            STATS[a] = {total: 0, match: 0};
            try {
                Interceptor.attach(ptr(a), {
                    onEnter: function(args){
                        STATS[a].total++;
                        const ctx = this.context;
                        const esp = ctx.esp;
                        const rawStack = [];
                        for (let i = 0; i < 12; i++){
                            try { rawStack.push('0x' +
                                esp.add(i*4).readU32().toString(16)); }
                            catch(e){ rawStack.push(null); }
                        }
                        // 扫栈找 cstr
                        const strs = [];
                        let matched = SQL_FILTER === null;
                        for (let i = 1; i < 12; i++){
                            let s = null;
                            try { s = readSql(ptr(esp.add(i*4).readU32()), 256); }
                            catch(e){}
                            if (s && s.length >= 4){
                                strs.push({slot: i, str: s.slice(0, 200)});
                                if (SQL_FILTER !== null &&
                                    s.indexOf(SQL_FILTER) >= 0){
                                    matched = true;
                                }
                            }
                        }
                        // 低频兜底：total 未超阈值时，即使 SQL filter 没命中
                        // 也 dump（SQL 常内联加载不进栈；低频天然锁定用户操作）
                        const lowFreq = STATS[a].total <= LOW_FREQ_THRESH;
                        if (!matched && !lowFreq) return;
                        if (matched) STATS[a].match++;

                        let acc = [];
                        try {
                            acc = Thread.backtrace(ctx, Backtracer.ACCURATE)
                                .slice(0, 10)
                                .map(function(ra){
                                    const raStr = ra.toString();
                                    if (ra.compare(base) < 0 ||
                                        ra.compare(wxEnd) >= 0){
                                        return {ret: raStr, in_module: false};
                                    }
                                    const prol = findPrologueBefore(ra, 16384);
                                    return {
                                        ret: raStr,
                                        func: prol ? prol.toString() : null,
                                        class_hint: prol ?
                                            nearbyClassName(prol) : null,
                                    };
                                });
                        } catch(e){}

                        send({t:'hit',
                              hookedAddr: a,
                              this_ecx: '0x' + ctx.ecx.toString(16),
                              esp_dw: rawStack,
                              stack_strs: strs,
                              bt: acc,
                              matched_filter: matched,
                              low_freq: lowFreq,
                              ts: Date.now()});
                    }
                });
            } catch(e){
                send({t:'err', where:'install', addr:a, msg:e.message});
            }
        });
        return true;
    },

    stats: function(){
        const out = [];
        ORDER.forEach(function(a){
            const s = STATS[a] || {total: 0, match: 0};
            out.push({addr: a, total: s.total, match: s.match});
        });
        return out;
    },
    bye: function(){ send({t:'bye'}); },
};

send({t:'ready'});
"""


def get_wxwork_pid() -> int:
    r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    for line in r.stdout.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.split()[-1])
    raise RuntimeError("WXWork.exe :9882 not listening; is 企微 running?")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=180,
                    help="hook 阶段最长运行秒数（默认 180）")
    ap.add_argument("--filter", type=str, default="replace into message_appinfo",
                    help="严格 SQL 过滤器；栈上任一 cstr 含此串才计 match")
    ap.add_argument("--anchor", type=str, default=None,
                    help="覆盖默认 anchor 候选（只用这一条）")
    ap.add_argument("--extra", type=str, default="",
                    help="除 discovery 结果外，额外附带 hook 的地址（逗号分隔）")
    ap.add_argument("--max-candidates", type=int, default=32,
                    help="至多 hook 多少个候选函数（避免灾难性 hook 数量）")
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID = {pid}")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"appinfo_hunter_{ts}.ndjson"
    summary_path = OUT_DIR / f"appinfo_hunter_summary_{ts}.json"

    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)

    hits: list[dict[str, Any]] = []
    ready = {"v": False}
    wx_base: dict[str, Any] = {}
    fp = ndjson_path.open("a", encoding="utf-8")

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                wx_base["base"] = p["base"]
                wx_base["size"] = p["size"]
                print(f"[+] wx base={p['base']} size={p['size']}")
            elif t == "hit":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n")
                fp.flush()
                strs = p.get("stack_strs", [])
                sql_hit = next((s for s in strs
                                if args.filter in s.get("str", "")), None)
                sql_show = (sql_hit["str"][:100] if sql_hit
                            else "<inline-SQL / not-in-stack>")
                tag = ("SQL-MATCH" if p.get("matched_filter")
                       else "LOW-FREQ" if p.get("low_freq")
                       else "HIT")
                print(f"[{tag}] @{p['hookedAddr']} this={p['this_ecx']} "
                      f"sql={sql_show!r}")
                for i, f in enumerate((p.get("bt") or [])[:8]):
                    func = f.get("func") or "-"
                    cls = f.get("class_hint") or ""
                    print(f"    #{i} ret={f['ret']} func={func}  {cls}")
            elif t == "err":
                print(f"[!] JS err: {p}")
            elif t == "bye":
                print("[BYE]")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    # ── 阶段 1：discovery ─────────────────────────────────────
    anchors = [args.anchor] if args.anchor else SQL_ANCHOR_CANDIDATES
    print(f"[*] discovery: trying {len(anchors)} SQL anchor(s) ...")
    disco = script.exports_sync.discover(anchors)

    print("─" * 60)
    print(f"[+] sql_anchor_used  = {disco.get('sql_anchor_used')!r}")
    print(f"[+] sql_addrs        = {disco.get('sql_addrs')}")
    print(f"[+] 1-hop code xrefs = {len(disco.get('code_xrefs') or [])}")
    print(f"[+] 1-hop data xrefs = {len(disco.get('data_xrefs') or [])}")
    if disco.get("hop2_code_xrefs"):
        print(f"[+] 2-hop code xrefs = {len(disco['hop2_code_xrefs'])}")
    cands = disco.get("candidates") or []
    print(f"[+] candidates       = {len(cands)}")
    for c in cands[:16]:
        hint = c.get("class_hint") or "(no class hint)"
        print(f"      {c['addr']}  votes={c['votes']}  {hint}")
    for n in disco.get("notes") or []:
        print(f"      · {n}")

    if not cands:
        print("[!] no candidates → abort")
        try:
            script.unload(); session.detach()
        except Exception:
            pass
        return 3

    cand_addrs = [c["addr"] for c in cands[: args.max_candidates]]
    extras = [x.strip() for x in args.extra.split(",") if x.strip()]
    addrs = cand_addrs + [a for a in extras if a not in cand_addrs]
    print("─" * 60)
    print(f"[*] installing {len(addrs)} hooks "
          f"({len(cand_addrs)} candidates + {len(extras)} extra) ...")
    print(f"[*] SQL filter = {args.filter!r}")

    # ── 阶段 2/3：hook + hunt ─────────────────────────────────
    script.exports_sync.install(addrs, args.filter)
    print(f"[*] hooks installed. Forward 1-3 messages within "
          f"{args.duration}s.")

    deadline = time.monotonic() + args.duration
    hb_interval = 10
    next_hb = time.monotonic() + hb_interval
    while time.monotonic() < deadline:
        time.sleep(1)
        if time.monotonic() >= next_hb:
            next_hb += hb_interval
            try:
                st = script.exports_sync.stats()
                el = int(args.duration - (deadline - time.monotonic()))
                nz = [x for x in st if x["match"] > 0 or x["total"] > 0]
                nz.sort(key=lambda x: (-x["match"], -x["total"]))
                summary = ", ".join(
                    f"{x['addr']}:m{x['match']}/t{x['total']}"
                    for x in nz[:6]
                )
                print(f"  [hb] elapsed={el}s reported={len(hits)}  | {summary}")
            except Exception as e:
                print(f"  [hb] stats err: {e}")

    try:
        script.exports_sync.bye()
        time.sleep(0.3)
    except Exception:
        pass
    fp.close()

    try:
        final_stats = script.exports_sync.stats()
    except Exception:
        final_stats = []

    # Winner 判定：match > 0（SQL 显式命中） 或 0 < total ≤ 20（低频独占）
    # 因为二跳候选的 SQL 通常是 `mov reg, offset TABLE` 内联加载，栈上没有
    # SQL 明文；这类"低频候选" total 数几乎等于用户操作次数
    def _is_winner(x: dict) -> bool:
        return x["match"] > 0 or (0 < x["total"] <= 20)

    ranked = sorted(final_stats,
                    key=lambda x: (-x["match"], -x["total"] if _is_winner(x)
                                   else x["total"]))
    winners = [x for x in ranked if _is_winner(x)]

    print("─" * 60)
    print(f"[+] hits reported (SQL-filtered) = {len(hits)}")
    print(f"[+] per-address stats (top by winner-heuristic):")
    for x in ranked[:20]:
        marker = ""
        if x["match"] > 0:
            marker = " ★ WINNER (SQL-match)"
        elif 0 < x["total"] <= 20:
            marker = " ★ WINNER (low-freq × forward count)"
        print(f"      {x['addr']}  match={x['match']:3d}  "
              f"total={x['total']:6d}{marker}")

    # 为方便下一步 hook（若 winner 是 wrapper 层），把 winner 的
    # top-1 bt frame func 也统计一下，作为"SendMessage 主入口候选"
    top_bt_funcs: list[dict[str, Any]] = []
    if winners:
        from collections import Counter
        c: Counter = Counter()
        class_hints: dict[str, str] = {}
        for h in hits:
            if h.get("hookedAddr") != winners[0]["addr"]:
                continue
            for f in (h.get("bt") or [])[:6]:
                fn = f.get("func")
                if fn:
                    c[fn] += 1
                    if f.get("class_hint") and fn not in class_hints:
                        class_hints[fn] = f["class_hint"]
        for fn, n in c.most_common(10):
            top_bt_funcs.append({"func": fn, "vote": n,
                                 "class_hint": class_hints.get(fn)})
        print("─" * 60)
        print(f"[+] winner={winners[0]['addr']}'s bt top funcs "
              f"(SendMessage-caller candidates):")
        for x in top_bt_funcs:
            hint = x["class_hint"] or "(no class hint)"
            print(f"      {x['func']}  vote={x['vote']}  {hint}")

    # RVA 附带存起来（未来若同版本二进制重启，可直接 rebase 复用）
    base_int = int(wx_base.get("base", "0x0"), 16)
    def _rva(a: str) -> Optional[str]:
        try:
            return hex(int(a, 16) - base_int)
        except Exception:
            return None

    summary = {
        "pid": pid,
        "ts": ts,
        "wx_base": wx_base.get("base"),
        "wx_size": wx_base.get("size"),
        "sql_filter": args.filter,
        "discovery": {
            "sql_anchor_used": disco.get("sql_anchor_used"),
            "sql_addrs": disco.get("sql_addrs"),
            "sql_addrs_rva": [_rva(a) for a in (disco.get("sql_addrs") or [])],
            "data_xrefs": disco.get("data_xrefs"),
            "hop2_code_xrefs": disco.get("hop2_code_xrefs"),
            "candidates": cands,
            "candidates_rva": [
                {**c, "rva": _rva(c["addr"])} for c in cands
            ],
            "notes": disco.get("notes"),
        },
        "hooked_addrs": addrs,
        "hits_reported": len(hits),
        "per_addr_stats": final_stats,
        "winners": winners,
        "winners_rva": [{**w, "rva": _rva(w["addr"])} for w in winners],
        "winner_bt_top_funcs": top_bt_funcs,
        "winner_bt_top_funcs_rva": [
            {**x, "rva": _rva(x["func"])} for x in top_bt_funcs
        ],
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    print(f"[+] ndjson  : {ndjson_path.name}")
    print(f"[+] summary : {summary_path.name}")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
