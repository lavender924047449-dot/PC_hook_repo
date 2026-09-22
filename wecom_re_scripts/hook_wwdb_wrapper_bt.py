# hook_wwdb_wrapper_bt.py — P2 首步 · 运行时 backtrace 拿 SendMessage 入口
# ================================================================
#
# 前置：先跑 `find_sendmessage_from_appinfo.py` 得到 wwdb_wrapper_addr。
#
# 本脚本：
#   * hook wwdb_wrapper_addr（onEnter）
#   * dump: this(ecx)、栈前 8 dword、backtrace(FUZZY + ACCURATE 双模)
#     · 每帧地址向前扫函数序言 → 得到 caller 函数入口
#     · 附近 2KB 内扫 `class wework::` 前缀 → 补 class_hint
#   * 用户手动转发 1–3 次即命中
#
# 输出：runtime/wecom_re/wwdb_wrapper_bt_<TS>.ndjson  （每次命中 1 行）
#       runtime/wecom_re/wwdb_wrapper_bt_summary_<TS>.json
#
# CLI:
#   & Python311 runtime/wecom_re/hook_wwdb_wrapper_bt.py \
#       --wrapper 0xb59427 --duration 120
#
#   （地址可从 sendmessage_discovery_<TS>.json.wwdb_wrapper_addr 拷贝）
# ================================================================

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


FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const base = wx.base;
const wxEnd = base.add(wx.size);
send({t:'info', base: base.toString(), size: wx.size});

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

function nearbyClassName(funcAddr){
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

function readSql(ptrArg, cap){
    cap = cap || 512;
    try { return ptrArg.readCString(cap); } catch(e){}
    return null;
}

let HITS_TOTAL = 0;      // wrapper 被调总次数（未过滤）
let HITS_MATCH = 0;      // 通过 SQL 过滤器的次数
let ADDR = null;
let SQL_FILTER = null;   // 只 dump arg0/[esp+8] cstr 中含此子串的命中
let PROBE_STACK_SLOTS = 12;  // 试 [esp+4..esp+48] 找 SQL 指针（thiscall 时 SQL 可能在 arg2）

rpc.exports = {
    install: function(wrapperAddr, sqlFilter){
        ADDR = ptr(wrapperAddr);
        SQL_FILTER = (sqlFilter && sqlFilter.length) ? sqlFilter : null;
        Interceptor.attach(ADDR, {
            onEnter: function(args){
                HITS_TOTAL++;
                const ctx = this.context;
                // thiscall: ecx = this；栈上 [esp+4..] = 实参
                const esp = ctx.esp;
                const rawStack = [];
                for (let i = 0; i < PROBE_STACK_SLOTS; i++){
                    try { rawStack.push('0x' + esp.add(i*4).readU32().toString(16)); }
                    catch(e){ rawStack.push(null); }
                }
                // 探测多个栈槽（wwdb 签名可能是 (this, sql) 或 (this, x, sql)）
                let stackStrs = [];
                let sqlProbe = null, sqlProbeSlot = -1;
                for (let i = 1; i <= PROBE_STACK_SLOTS - 1; i++){
                    let s = null;
                    try { s = readSql(ptr(esp.add(i*4).readU32()), 256); }
                    catch(e){}
                    if (s && s.length >= 4){
                        stackStrs.push({slot: i, str: s.slice(0, 100)});
                        if (sqlProbe === null){ sqlProbe = s; sqlProbeSlot = i; }
                    }
                }

                // 过滤器：只 dump 匹配 SQL_FILTER 的命中
                if (SQL_FILTER !== null){
                    let matched = false;
                    for (let i = 0; i < stackStrs.length; i++){
                        if (stackStrs[i].str.indexOf(SQL_FILTER) >= 0){
                            matched = true; break;
                        }
                    }
                    if (!matched) return;
                }
                HITS_MATCH++;

                // FUZZY backtrace（EBP 链常被 FPO 优化，未必可用）
                let fuzzy = [];
                try {
                    fuzzy = Thread.backtrace(ctx, Backtracer.FUZZY)
                            .slice(0, 12)
                            .map(function(a){ return a.toString(); });
                } catch(e){}
                // ACCURATE backtrace
                let accurate = [];
                try {
                    accurate = Thread.backtrace(ctx, Backtracer.ACCURATE)
                            .slice(0, 12)
                            .map(function(a){ return a.toString(); });
                } catch(e){}

                // 每帧回溯函数入口 + class hint
                function digest(chain){
                    return chain.map(function(retStr){
                        const ret = ptr(retStr);
                        // 仅关心 WXWork.exe 内地址
                        if (ret.compare(base) < 0 || ret.compare(wxEnd) >= 0){
                            return {ret: retStr, in_module: false};
                        }
                        const prol = findPrologueBefore(ret, 16384);
                        return {
                            ret: retStr,
                            func: prol ? prol.toString() : null,
                            class_hint: prol ? nearbyClassName(prol) : null,
                        };
                    });
                }

                send({t:'hit',
                      hitNo: HITS_MATCH,
                      hitTotal: HITS_TOTAL,
                      tid: this.threadId,
                      this_ecx: '0x' + ctx.ecx.toString(16),
                      esp_dw: rawStack,
                      stack_strs: stackStrs,
                      sql_probe: sqlProbe,
                      sql_probe_slot: sqlProbeSlot,
                      bt_fuzzy: digest(fuzzy),
                      bt_accurate: digest(accurate),
                      ts: Date.now()});
            }
        });
        return true;
    },
    stats: function(){ return {total: HITS_TOTAL, match: HITS_MATCH}; },
    bye: function(){ send({t:'bye', hits: HITS_MATCH, total: HITS_TOTAL}); },
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
    ap.add_argument("--wrapper", required=True,
                    help="wwdb_wrapper_addr（从 sendmessage_discovery JSON 拷贝）")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=180,
                    help="最长运行秒数（默认 180 = 3min）")
    ap.add_argument("--filter", type=str, default="message_appinfo",
                    help="SQL 子串过滤器；只 dump 栈上任一 cstr 含此串的命中。"
                         "设为空串 '' 关闭过滤器（会大量刷屏，勿在 prepare 类"
                         "高频 wrapper 上使用）")
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID = {pid}")
    print(f"[*] hooking wwdb wrapper @ {args.wrapper}")
    print(f"[*] SQL filter = {args.filter!r} "
          f"({'ON' if args.filter else 'OFF—will dump ALL hits'})")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"wwdb_wrapper_bt_{ts}.ndjson"
    summary_path = OUT_DIR / f"wwdb_wrapper_bt_summary_{ts}.json"

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
                print(f"[+] wx base={p['base']} size={p['size']}")
            elif t == "hit":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n")
                fp.flush()
                # 打印精简版
                acc_frames = p.get("bt_accurate", [])[:8]
                sql_probe = p.get("sql_probe")
                sql_probe_str = (sql_probe[:80] + "..."
                                 if sql_probe and len(sql_probe) > 80
                                 else sql_probe)
                print(f"[HIT #{p['hitNo']}/{p.get('hitTotal')}] "
                      f"this={p['this_ecx']} tid={p['tid']} "
                      f"sql@slot{p.get('sql_probe_slot')}={sql_probe_str!r}")
                for i, f in enumerate(acc_frames):
                    func = f.get("func") or "-"
                    cls = f.get("class_hint") or ""
                    print(f"    #{i} ret={f['ret']} func={func}  {cls}")
            elif t == "bye":
                print(f"[BYE] hits={p.get('hits')}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    print("[*] installing hook ...")
    script.exports_sync.install(args.wrapper, args.filter or "")
    print(f"[*] hook installed. Now forward 1-3 messages in 企微 within "
          f"{args.duration}s ...")

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        time.sleep(2)
        el = int(args.duration - (deadline - time.monotonic()))
        try:
            st = script.exports_sync.stats()
            print(f"  [hb] elapsed={el}s hits_match={len(hits)} "
                  f"hits_total={st.get('total')}")
        except Exception:
            print(f"  [hb] elapsed={el}s hits_match={len(hits)}")

    try:
        script.exports_sync.bye()
        time.sleep(0.3)
    except Exception:
        pass
    fp.close()

    # 汇总：从所有 accurate frames 里投票 SendMessage caller 候选
    func_vote: Counter = Counter()
    class_hint_by_func: dict[str, str] = {}
    for h in hits:
        for f in h.get("bt_accurate", []):
            fn = f.get("func")
            if fn:
                func_vote[fn] += 1
                if f.get("class_hint") and fn not in class_hint_by_func:
                    class_hint_by_func[fn] = f["class_hint"]

    top = []
    for fn, n in func_vote.most_common(20):
        top.append({"func": fn, "vote": n,
                    "class_hint": class_hint_by_func.get(fn)})

    summary = {
        "pid": pid,
        "ts": ts,
        "wrapper": args.wrapper,
        "hits_total": len(hits),
        "candidates_top20": top,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                            encoding="utf-8")

    print("─" * 60)
    print(f"[+] hits total = {len(hits)}")
    print(f"[+] top 10 SendMessage caller candidates (by vote):")
    for c in top[:10]:
        hint = c["class_hint"] or "(no class hint)"
        print(f"      {c['func']}  vote={c['vote']}  {hint}")
    print(f"[+] ndjson  : {ndjson_path.name}")
    print(f"[+] summary : {summary_path.name}")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
