# dump_upstream_sendmessage.py — P2 · 向上游追 hijack 点
# ================================================================
#
# 前置发现（第二十/二十一轮）：
#   0x8dd8202 hijack 失败 —— 我们在 6 个 payload buffer 里 patch 掉的
#   S:xxx_yyy 都是"路由决策**之后**的痕迹副本"（DB/日志/追踪），
#   真正的路由字段在更上游。
#
# 本脚本目标：
#   hook 0x8d59e82（0x8cc1612 SchemaManager 的上游，SendMessage 派发层）
#   每次转发在 this / stack / 各字段里找**干净的 conv_id**——
#   即 char* 首字节起就直接是 "S:" 或 "R:" 或 "G:"（而不是埋在 payload
#   偏移几百字节处的子串）。
#
# 判定：
#   · 命中 clean_conv → 说明该层收到 conv_id 作为独立参数，是 hijack 金矿
#   · 只命中 embedded_conv → 序列化已发生，与 0x8dd8202 同层，无意义
#   · 都没命中 → 需要再往上找
#
# 用法：
#   & Python311 runtime/wecom_re/dump_upstream_sendmessage.py --duration 90
#   → 90 秒内做 2-3 次 FTA→外部转发
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

DEFAULT_TARGET = "0x8d59e82"

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
send({t:'info', base: wx.base.toString()});

const CONV_RE = /^(S:\d{10,20}_\d{10,20}|R:[\w:_-]{10,64}|G:[\w:_-]{10,64})/;
const CONV_EMBED_RE = /(S:\d{10,20}_\d{10,20}|R:[\w:_-]{10,64}|G:[\w:_-]{10,64})/;

function readCStr(p, cap){
    try { return p.readCString(cap || 256); } catch(e){ return null; }
}
function readBytes(p, n){
    try { return new Uint8Array(p.readByteArray(n)); }
    catch(e){ return null; }
}

// 判定：cstring 首字节起就是 conv_id → clean（金矿）
function tryClean(rawU32){
    if (!rawU32) return null;
    const cs = readCStr(ptr(rawU32), 128);
    if (!cs) return null;
    const m = CONV_RE.exec(cs);
    return m ? m[0] : null;
}
// 判定：buffer 内埋着 conv_id → embedded（意义不大）
function tryEmbed(rawU32){
    if (!rawU32) return null;
    const bytes = readBytes(ptr(rawU32), 2048);
    if (!bytes) return null;
    let s = '';
    for (let i = 0; i < bytes.length; i++){
        const b = bytes[i];
        if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
        else s += '\x01';
    }
    const m = CONV_EMBED_RE.exec(s);
    if (!m) return null;
    return {conv: m[0], at: m.index};
}

let TARGET_ADDR = null;
let COUNT = 0;

function inspectContext(ecx, esp, tag){
    const cleanFound = [];
    const embedFound = [];
    // 扫 this 前 32 dword
    for (let off = 0; off <= 128; off += 4){
        let raw = 0;
        try { raw = ecx.add(off).readU32(); } catch(e){ continue; }
        const c = tryClean(raw);
        if (c) cleanFound.push({loc:'this+0x'+off.toString(16), conv:c,
                                raw:'0x'+raw.toString(16)});
        else {
            const e = tryEmbed(raw);
            if (e) embedFound.push({loc:'this+0x'+off.toString(16),
                                    conv:e.conv, at:e.at,
                                    raw:'0x'+raw.toString(16)});
        }
    }
    // 扫栈前 20 dword
    for (let slot = 0; slot <= 20; slot++){
        let raw = 0;
        try { raw = esp.add(slot*4).readU32(); } catch(e){ continue; }
        const c = tryClean(raw);
        if (c) cleanFound.push({loc:'stk['+slot+']', conv:c,
                                raw:'0x'+raw.toString(16)});
        else {
            const e = tryEmbed(raw);
            if (e) embedFound.push({loc:'stk['+slot+']', conv:e.conv,
                                    at:e.at, raw:'0x'+raw.toString(16)});
        }
    }
    return {clean: cleanFound, embed: embedFound};
}

rpc.exports = {
    install: function(addrStr){
        TARGET_ADDR = ptr(addrStr);
        Interceptor.attach(TARGET_ADDR, {
            onEnter: function(args){
                COUNT++;
                const ecx = this.context.ecx;
                const esp = this.context.esp;
                const info = inspectContext(ecx, esp, 'onEnter');
                if (info.clean.length === 0 && info.embed.length === 0) return;
                send({t:'hit',
                      seq: COUNT,
                      addr: addrStr,
                      this_addr: ecx.toString(),
                      esp: esp.toString(),
                      tid: this.threadId,
                      clean: info.clean,
                      embed: info.embed});
            }
        });
        send({t:'installed', addr: addrStr});
    },
    stats: function(){ return {count: COUNT}; },
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
    ndjson_path = OUT_DIR / f"upstream_{ts}.ndjson"

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
            elif t == "installed":
                print(f"[+] hook installed @ {p['addr']}")
            elif t == "hit":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n"); fp.flush()
                print(f"\n[HIT #{p['seq']}] this={p['this_addr']}  esp={p['esp']}  tid={p['tid']}")
                if p['clean']:
                    print(f"  ★ CLEAN conv_id \u2014 \u91d1\u77ff\uff01\uff01\uff01")
                    for c in p['clean']:
                        print(f"    {c['loc']:14s}  raw={c['raw']:12s}  conv={c['conv']!r}")
                if p['embed']:
                    print(f"  \u25cb embedded (\u5df2\u5e8f\u5217\u5316\u7684 payload):")
                    for e in p['embed'][:5]:
                        print(f"    {e['loc']:14s}  raw={e['raw']:12s}  conv={e['conv']!r}  @ buf+0x{e['at']:x}")
                    if len(p['embed']) > 5:
                        print(f"    ... 另 {len(p['embed']) - 5} 处")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)
    script.exports_sync.install(args.target)
    print(f"\n[*] armed for {args.duration}s. 现在做 2-3 次 FTA→外部联系人 转发\n")

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        time.sleep(1)

    fp.close()
    try:
        st = script.exports_sync.stats()
        n_clean = sum(1 for h in hits if h.get('clean'))
        n_embed = sum(1 for h in hits if h.get('embed') and not h.get('clean'))
        print()
        print(f"[+] final: total hits at {args.target} = {st['count']}")
        print(f"          with clean conv_id  = {n_clean}  \u2190 hijack \u91d1\u77ff\u5019\u9009")
        print(f"          with embedded only  = {n_embed}  \u2190 \u540c 0x8dd8202\u5c42\u6b21\uff0c\u65e0\u7528")
    except Exception:
        pass
    print(f"[+] → {ndjson_path.name}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
