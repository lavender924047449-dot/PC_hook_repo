# hook_sendmessage_chain.py — P2 · SendMessage 调用链 hook + A/B 差分
# ================================================================
#
# 前置数据（第十八轮 winner 0x8cbc452 的 backtrace，3 次转发 100% 稳定）：
#
#   root ← 0x35014c2 → 0x34fd622 → 0x8d59e82 → 0x8cc1612
#       ↓
#       0x8dd5eb2 → 0x8dd6f72 → 0x8dd8202 → 0x8dd91a2
#       ↓（PostSendMessageTask2 编译单元集群）
#       0x8cbbfa2 → 0x8ddad12 → 0x8cbc452 (winner)
#
# 本脚本：
#   1. 从 A(FTA→FTA) / B(FTA→外部) 两轮转发中，对下面 6 个稳定 caller
#      + winner 各 hook onEnter
#   2. 每次 hit dump:
#        · this (ecx)  → 深度 512 字节
#        · 栈前 16 dword
#        · 每个 dword 作 ptr 尝试 deref 到 cstring / utf16 / 512 字节 hex
#        · 每帧的 backtrace（3 帧即可，因为已知稳定）
#   3. 结束时按 (round, hooked_addr) 分组，用户后续可离线做 A/B diff
#      找出**随目标会话变化**的字段 offset —— 那就是 dest_conv_id
#
# 工作模式：
#   * 无 --round 参数：hook 全部，用户手动跑两次（每次前用 --round A / B 覆写）
#   * 或用 sentinel 文件切换 round：Frida 侧检测 SENTINEL 文件时间变化
#
# 输出：
#   runtime/wecom_re/sendchain_<TS>_<round>.ndjson
#
# 推荐操作流程（同一进程内 A/B）：
#   Terminal 1:
#     & Python311 runtime/wecom_re/hook_sendmessage_chain.py --round A \
#         --hook 0x8cbc452,0x8ddad12,0x8cbbfa2,0x8dd91a2,0x8dd8202,0x8dd6f72,0x8dd5eb2,0x8cc1612 \
#         --duration 120
#     → 手动转发 3 次到 FTA
#
#   Terminal 2（同进程，可另开）：
#     & Python311 runtime/wecom_re/hook_sendmessage_chain.py --round B \
#         --hook <same-addrs> --duration 120
#     → 手动转发 3 次到外部联系人
#
#   分析：
#     & Python311 runtime/wecom_re/diff_sendchain.py \
#         sendchain_<TS_A>_A.ndjson sendchain_<TS_B>_B.ndjson
#
# 首次跑请用第十八轮探到的绝对地址；若企微再重启，先跑
# hook_appinfo_candidates.py 重新拿 winner，再拿其 bt 里 vote=N 的 top 6 caller
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


FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const base = wx.base;
const wxEnd = base.add(wx.size);
send({t:'info', base: base.toString(), size: wx.size});

function readCString(p, cap){
    cap = cap || 512;
    try { return p.readCString(cap); } catch(e){}
    return null;
}
function readUtf16(p, cap){
    cap = cap || 512;
    try { return p.readUtf16String(cap); } catch(e){}
    return null;
}
function hexBytes(p, n){
    if (n <= 0 || n > 4096) return null;
    try {
        const buf = new Uint8Array(p.readByteArray(n));
        let h = '';
        for (let i = 0; i < buf.length; i++){
            const b = buf[i]; if (b < 16) h += '0'; h += b.toString(16);
        }
        return h;
    } catch(e){ return null; }
}

// deref 一个 32-bit 值当作 ptr 尝试解读
function derefValue(v){
    if (v === 0) return null;
    try {
        const p = ptr(v);
        // 只关心指向可读内存的
        const cstr = readCString(p, 256);
        const u16  = readUtf16(p, 128);
        // 前 32 字节 hex 快照
        const head = hexBytes(p, 32);
        // 判 cstr 是否"真正可读"（避免误报）
        const cstrOk = (cstr && cstr.length >= 3 &&
                        /[\x20-\x7e]/.test(cstr[0]));
        const u16Ok  = (u16 && u16.length >= 3 &&
                        /[\u0020-\u007e\u4e00-\u9fff]/.test(u16[0]));
        return {
            cstr: cstrOk ? cstr : null,
            u16: u16Ok ? u16 : null,
            head_hex: head,
        };
    } catch(e){ return null; }
}

let ROUND = 'X';       // 由 Python 侧传入
let HOOKED = {};       // {addr_str: hit_count}
let SEQ = 0;

rpc.exports = {
    setRound: function(r){ ROUND = r; },
    install: function(addrList){
        addrList.forEach(function(a){
            HOOKED[a] = 0;
            try {
                Interceptor.attach(ptr(a), {
                    onEnter: function(args){
                        HOOKED[a]++;
                        SEQ++;
                        const ctx = this.context;
                        const esp = ctx.esp;
                        const ecx = ctx.ecx;
                        // 栈前 16 dword
                        const stack = [];
                        for (let i = 0; i < 16; i++){
                            let raw = null, deref = null;
                            try {
                                raw = esp.add(i*4).readU32();
                                deref = derefValue(raw);
                            } catch(e){}
                            stack.push({slot: i, raw_hex: raw !== null ?
                                        '0x' + raw.toString(16) : null,
                                        deref: deref});
                        }
                        // this 对象前 512 字节
                        const thisHead = hexBytes(ecx, 512);
                        // this 对象前 32 dword 各自 deref（找嵌套字符串）
                        const thisDW = [];
                        for (let i = 0; i < 32; i++){
                            let raw = null, deref = null;
                            try {
                                raw = ecx.add(i*4).readU32();
                                deref = derefValue(raw);
                            } catch(e){}
                            thisDW.push({off: i*4, raw_hex: raw !== null ?
                                         '0x' + raw.toString(16) : null,
                                         deref: deref});
                        }
                        // 简短 bt（3 帧就够，为了追溯）
                        let bt = [];
                        try {
                            bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
                                .slice(0, 5).map(function(r){
                                    return r.toString();
                                });
                        } catch(e){}
                        send({t:'hit',
                              round: ROUND,
                              seq: SEQ,
                              hookedAddr: a,
                              hitNo: HOOKED[a],
                              tid: this.threadId,
                              this_ecx: '0x' + ecx.toString(16),
                              this_head_hex: thisHead,
                              this_dw: thisDW,
                              stack: stack,
                              bt: bt,
                              ts: Date.now()});
                    }
                });
            } catch(e){
                send({t:'err', addr: a, msg: e.message});
            }
        });
        return true;
    },
    stats: function(){
        const r = {};
        Object.keys(HOOKED).forEach(function(k){ r[k] = HOOKED[k]; });
        return r;
    },
    bye: function(){ send({t:'bye', total: SEQ}); },
};

send({t:'ready'});
"""


DEFAULT_CHAIN = ",".join([
    "0x8cbc452",   # winner (message_appinfo INSERT)
    "0x8ddad12",   # 直接 caller
    "0x8cbbfa2",   # winner 的容器函数
    "0x8dd91a2",   # PostSendMessageTask2 集群
    "0x8dd8202",
    "0x8dd6f72",
    "0x8dd5eb2",
    "0x8cc1612",   # Task dispatcher 层
])


def get_wxwork_pid() -> int:
    r = subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    for line in r.stdout.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.split()[-1])
    raise RuntimeError("WXWork.exe :9882 not listening")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=str, required=True,
                    help="轮次标记（A / B / C 等）；写入每条 hit 与文件名")
    ap.add_argument("--hook", type=str, default=DEFAULT_CHAIN,
                    help="逗号分隔的绝对地址列表；默认使用第十八轮的 8 个函数")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=120)
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    addrs = [x.strip() for x in args.hook.split(",") if x.strip()]
    print(f"[*] attaching PID = {pid}   round = {args.round!r}")
    print(f"[*] hooking {len(addrs)} chain functions:")
    for a in addrs:
        print(f"      {a}")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"sendchain_{ts}_{args.round}.ndjson"

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
                print(f"[+] wx base={p['base']}")
            elif t == "hit":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n")
                fp.flush()
                # 精简打印：hookedAddr + 第一条有意义的 deref
                interesting = []
                for e in (p.get("stack") or [])[:16]:
                    d = e.get("deref") or {}
                    s = d.get("cstr") or d.get("u16")
                    if s and len(s) >= 4:
                        interesting.append(f"stk[{e['slot']}]={s[:60]!r}")
                        if len(interesting) >= 3:
                            break
                for e in (p.get("this_dw") or [])[:32]:
                    d = e.get("deref") or {}
                    s = d.get("cstr") or d.get("u16")
                    if s and len(s) >= 4:
                        interesting.append(f"this+{e['off']:02x}={s[:60]!r}")
                        if len(interesting) >= 6:
                            break
                print(f"[HIT {p['round']}#{p['seq']:03d}] "
                      f"@{p['hookedAddr']} this={p['this_ecx']}  "
                      + " | ".join(interesting))
            elif t == "err":
                print(f"[!] JS err: {p}")
            elif t == "bye":
                print(f"[BYE] total={p.get('total')}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    script.exports_sync.setRound(args.round)
    script.exports_sync.install(addrs)
    print(f"[*] installed. Now do 2-3 forwards for round {args.round!r} "
          f"within {args.duration}s.")

    deadline = time.monotonic() + args.duration
    next_hb = time.monotonic() + 15
    while time.monotonic() < deadline:
        time.sleep(1)
        if time.monotonic() >= next_hb:
            next_hb += 15
            try:
                st = script.exports_sync.stats()
                el = int(args.duration - (deadline - time.monotonic()))
                per = ", ".join(f"{k}:{v}" for k, v in st.items() if v > 0)
                print(f"  [hb] elapsed={el}s total={len(hits)}  | {per}")
            except Exception as e:
                print(f"  [hb] err: {e}")

    try:
        script.exports_sync.bye()
        time.sleep(0.3)
    except Exception:
        pass
    fp.close()
    print(f"[+] {len(hits)} hits → {ndjson_path.name}")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
