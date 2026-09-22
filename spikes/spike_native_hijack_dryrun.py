# spike_native_hijack_dryrun.py — P2 · Native hijack 只读探针
# ================================================================
#
# 目标：验证 0x8dd8202 上的 SendMessage 过滤器精度，为 hijack PoC 铺路。
#
# 已知（第十九轮）：
#   0x8dd8202 fires 18 次/分钟，其中 SendMessage 相关只占 ~2 次。
#   要 hijack 就必须**只在 SendMessage 时**改写 [ecx+0x64]，
#   否则会破坏 typing / heartbeat / DB update 等无关调用。
#
# 过滤器候选（onEnter 时判断，全命中才算 SendMessage）：
#   F1: [ecx+0x64] deref cstr 长度 >= 10  且 前 2 字符 = "S:" 或 "R:" 或全数字
#   F2: [ecx+0x6c] deref cstr 前 7 字符 = "http://"
#   F3: [ecx+0x50] deref cstr 包含 "network::"
#
# 三层 AND 匹配 → 判定为 SendMessage，只打印不改写。
#
# 用法：
#   & Python311 spikes/spike_native_hijack_dryrun.py --duration 120
#   → 120 秒内做：3 次 FTA→FTA + 3 次 FTA→外部
#   期望：过滤器 6 次全命中、非 SendMessage 调用 0 命中
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

TARGET = "0x8dd8202"

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
send({t:'info', base: wx.base.toString()});

function readCStr(p, cap){
    try { return p.readCString(cap || 200); } catch(e){ return null; }
}
function derefCstr(base, off){
    try {
        const raw = base.add(off).readU32();
        if (raw === 0) return null;
        return readCStr(ptr(raw), 200);
    } catch(e){ return null; }
}
// [ecx+0x64] 指向的是**已序列化 payload buffer**，conv_id 是里面的子串。
// 用 Memory.scan 在 buffer 头 2KB 内找 "S:xxx_yyy" / "R:xxx" 模式。
const CONV_RE = /(S:\d{10,20}_\d{10,20}|R:[\w:_-]{10,64}|G:[\w:_-]{10,64})/;
function looksConvId(p_or_s){
    // 兼容旧调用（传字符串）
    if (typeof p_or_s === 'string') {
        const m = CONV_RE.exec(p_or_s);
        return m ? m[0] : null;
    }
    return null;
}
function scanBufferForConvId(ptrRaw){
    if (!ptrRaw || ptrRaw === 0) return null;
    try {
        // 尝试读 2KB 二进制，扫 ASCII 子串
        const bytes = new Uint8Array(ptr(ptrRaw).readByteArray(2048));
        // 把字节里所有可打印 ASCII 段拼起来，用非打印字符做分隔
        let s = '';
        for (let i = 0; i < bytes.length; i++){
            const b = bytes[i];
            if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
            else s += '\x01';   // 分隔占位
        }
        const m = CONV_RE.exec(s);
        return m ? m[0] : null;
    } catch(e){ return null; }
}

let COUNT_TOTAL = 0;
let COUNT_MATCH = 0;
let COUNT_F1 = 0, COUNT_F2 = 0, COUNT_F3 = 0;

rpc.exports = {
    install: function(){
        Interceptor.attach(ptr('""" + TARGET + r"""'), {
            onEnter: function(args){
                COUNT_TOTAL++;
                const ecx = this.context.ecx;
                // 在多个候选 offset 的 buffer 内扫 conv_id
                //（先前误以为 conv_id 是 char*，实际是内嵌于序列化 payload 里的子串）
                const OFFSETS = [0x64, 0x6c, 0x70, 0x48, 0x50, 0x58];
                let convFound = null, convOff = null;
                for (let i = 0; i < OFFSETS.length; i++){
                    const off = OFFSETS[i];
                    let raw = 0;
                    try { raw = ecx.add(off).readU32(); } catch(e){ continue; }
                    if (!raw) continue;
                    const m = scanBufferForConvId(raw);
                    if (m) { convFound = m; convOff = off; break; }
                }
                const url  = derefCstr(ecx, 0x6c);
                const net  = derefCstr(ecx, 0x50);

                const f1 = !!convFound;
                const f2 = (url && url.length >= 7 && url.slice(0, 7) === 'http://');
                const f3 = (net && net.indexOf('network::') !== -1);

                if (f1) COUNT_F1++;
                if (f2) COUNT_F2++;
                if (f3) COUNT_F3++;

                const matched = f1;   // 只要能找到 conv_id 就算命中
                if (matched) COUNT_MATCH++;

                // 命中就上报；每 200 次也发一次心跳看基线
                if (matched) {
                    send({t:'hit',
                          seq: COUNT_TOTAL,
                          matched: !!matched,
                          f1: !!f1, f2: !!f2, f3: !!f3,
                          conv: convFound,
                          conv_off: convOff,
                          url: url ? url.slice(0, 80) : null,
                          net: net ? net.slice(0, 80) : null,
                          this_addr: ecx.toString(),
                          tid: this.threadId});
                }
            }
        });
        send({t:'installed'});
    },
    stats: function(){
        return {total: COUNT_TOTAL, matched: COUNT_MATCH,
                f1_only: COUNT_F1, f2: COUNT_F2, f3: COUNT_F3};
    },
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
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=120)
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID = {pid}, target = {TARGET}")
    print(f"[*] filter = F1(conv_id shape) AND (F2(url http://) OR F3(network::))")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"hijack_dryrun_{ts}.ndjson"

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
                print(f"[+] hook installed")
            elif t == "hit":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n")
                fp.flush()
                mark = "★ MATCHED" if p["matched"] else "  F1-only"
                fs = f"F1={int(p['f1'])} F2={int(p['f2'])} F3={int(p['f3'])}"
                print(f"[{mark}] seq={p['seq']:3d} {fs}  "
                      f"conv={p['conv']!r}  url={p['url']!r}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    script.exports_sync.install()
    print()
    print(f"[*] armed for {args.duration}s. 请在此期间做：")
    print(f"    · 3 次 FTA→FTA 转发（期望 F1 命中，F2/F3 可能不命中 → matched=false）")
    print(f"    · 3 次 FTA→外部联系人 转发（期望 F1+F2+F3 全命中 → matched=true）")
    print()

    deadline = time.monotonic() + args.duration
    next_hb = time.monotonic() + 20
    while time.monotonic() < deadline:
        time.sleep(1)
        if time.monotonic() >= next_hb:
            next_hb += 20
            try:
                st = script.exports_sync.stats()
                print(f"  [hb] total={st['total']}  matched={st['matched']}  "
                      f"F1={st['f1_only']} F2={st['f2']} F3={st['f3']}")
            except Exception:
                pass

    fp.close()
    try:
        st = script.exports_sync.stats()
        print()
        print(f"[+] final: total 0x8dd8202 hits={st['total']}")
        print(f"          matched (F1 AND (F2||F3)) = {st['matched']}")
        print(f"          F1={st['f1_only']}  F2={st['f2']}  F3={st['f3']}")
    except Exception:
        pass
    print(f"[+] wrote {len(hits)} interesting hits → {ndjson_path.name}")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
