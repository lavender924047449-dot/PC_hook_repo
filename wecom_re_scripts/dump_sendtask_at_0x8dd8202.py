# dump_sendtask_at_0x8dd8202.py — 精细 dump SendMessageTask 结构
# ================================================================
#
# 前置结论（第十九轮 A/B 差分）：
#   0x8dd8202 = SendMessage 主处理入口（PostSendMessageTask2::Execute 或 SerializeAndSend）
#   ecx = SendMessageTask * (thiscall)
#   [ecx+0x64] = dest_conv_id  (std::string / CString)
#
# 本脚本目标（验证 + 深挖）：
#   1. 每次 hit，把 this 前 256 字节按 dword 逐个尝试 deref：
#        · 作为 char* 读 cstring
#        · 作为 wchar_t* 读 utf-16
#        · 作为 std::string 头（[ptr, size, capacity]）
#        · 作为 std::vector 头（[begin, end, cap]），列出前 8 个元素
#   2. 特别关注：
#        · this+0x64 → dest_conv_id（已确认）
#        · 找 msg_ids vector（有 3 个连续 ptr 且 diff = N*8）
#        · 找 msg_type / send_time / client_msg_id 等 int32/int64 字段
#   3. 输出 ndjson + 人类可读的字段快照表
#
# 用法：
#   & Python311 runtime/wecom_re/dump_sendtask_at_0x8dd8202.py --duration 60
#   → 60 秒内手动转发 1-2 条（FTA→外部 效果最好）
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

DEFAULT_TARGET = "0x8dd8202"

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const wxBase = wx.base;
const wxEnd  = wxBase.add(wx.size);
send({t:'info', base: wxBase.toString(), size: wx.size});

let TARGET = null;

function inWx(p){
    try { return p.compare(wxBase) >= 0 && p.compare(wxEnd) < 0; }
    catch(e){ return false; }
}
function inHeap(p){
    // 快速判断：非 null 非 wxwork 段，但可读
    if (p.isNull()) return false;
    try { p.readU8(); return true; } catch(e){ return false; }
}
function readCStr(p, cap){
    try { return p.readCString(cap || 256); } catch(e){ return null; }
}
function readW(p, cap){
    try { return p.readUtf16String(cap || 128); } catch(e){ return null; }
}
function hexHead(p, n){
    if (n <= 0) return null;
    try {
        const b = new Uint8Array(p.readByteArray(n));
        let s = '';
        for (let i = 0; i < b.length; i++){
            const v = b[i]; if (v < 16) s += '0'; s += v.toString(16);
        }
        return s;
    } catch(e){ return null; }
}
// 判"看起来是可打印字符串"（严格：至少 3 个 ASCII 或 CJK）
function looksPrintable(s){
    if (!s || s.length < 3) return false;
    let ok = 0;
    for (let i = 0; i < Math.min(s.length, 32); i++){
        const c = s.charCodeAt(i);
        if ((c >= 0x20 && c <= 0x7e) || (c >= 0x4e00 && c <= 0x9fff)) ok++;
    }
    return ok >= 3;
}
// 尝试识别 std::string(SSO) 或 std::string(heap)：
//   MSVC 15+ std::string 内部布局：
//     [union {char sso[16]; char*ptr}; size_t size; size_t capacity]
//   若 capacity >= 16 → heap 模式，ptr = *first_dword
//   若 capacity < 16 → SSO 模式，字符串就在 first 16 字节
// 我们不知道位置，就都试。
function tryStdString(base){
    try {
        const cap = base.add(20).readU32(); // offset 20 = capacity (32-bit)
        const size = base.add(16).readU32();
        if (cap >= 15 && cap < 0x100000 && size < cap) {
            // heap mode: ptr at offset 0
            const p = base.readPointer();
            if (inHeap(p)) {
                const s = readCStr(p, Math.min(size + 1, 512));
                if (looksPrintable(s)) return {mode:'heap', size:size, cap:cap, val:s};
            }
        }
        if (cap < 16 && size < 16) {
            // SSO mode
            const s = readCStr(base, 16);
            if (looksPrintable(s)) return {mode:'sso', size:size, cap:cap, val:s};
        }
    } catch(e){}
    return null;
}
// 尝试 std::vector<T*>：3 个连续 ptr + capacity - begin 可被 4 整除
function tryStdVector(base){
    try {
        const b = base.readPointer();
        const e = base.add(4).readPointer();
        const c = base.add(8).readPointer();
        if (b.isNull() || e.compare(b) < 0 || c.compare(e) < 0) return null;
        const spanE = e.sub(b).toInt32();
        const spanC = c.sub(b).toInt32();
        if (spanE > 0 && spanE <= 4096 && spanC >= spanE && (spanE % 4 === 0)) {
            // 尝试作 int32 / int64 / ptr 列表
            const elemSize = 4;  // 先猜 4
            const n = spanE / elemSize;
            if (n > 32) return null;
            const items = [];
            for (let i = 0; i < n; i++){
                try { items.push('0x' + b.add(i*elemSize).readU32().toString(16)); }
                catch(e){ items.push('??'); }
            }
            // 再猜 8 字节（int64/msg_id）
            let items8 = null;
            if (spanE % 8 === 0 && spanE / 8 <= 32) {
                items8 = [];
                for (let i = 0; i < spanE/8; i++){
                    try {
                        const lo = b.add(i*8).readU32();
                        const hi = b.add(i*8+4).readU32();
                        items8.push('0x' + hi.toString(16) + lo.toString(16).padStart(8,'0'));
                    } catch(e){ items8.push('??'); }
                }
            }
            return {span_bytes:spanE, cap_bytes:spanC,
                    as_u32: items, as_u64: items8};
        }
    } catch(e){}
    return null;
}

function dumpSendTask(ecx){
    const out = {this_addr: ecx.toString(), fields: []};
    // 遍历 offset 0..256 每 4 字节
    for (let off = 0; off <= 128; off += 4){
        const cell = {off: off};
        try {
            const raw = ecx.add(off).readU32();
            cell.raw = '0x' + raw.toString(16);
            if (raw !== 0) {
                const p = ptr(raw);
                if (inHeap(p)) {
                    const cs = readCStr(p, 200);
                    if (looksPrintable(cs)) cell.cstr = cs;
                    const ws = readW(p, 100);
                    if (looksPrintable(ws) && (!cs || ws.length > cs.length)) cell.w = ws;
                }
            }
            // 每个 offset 也尝试 std::string SSO/heap 识别
            const ss = tryStdString(ecx.add(off));
            if (ss) cell.std_string = ss;
            // 每 4-byte 对齐 offset 尝试 vector
            const vv = tryStdVector(ecx.add(off));
            if (vv) cell.std_vector = vv;
        } catch(e){
            cell.err = e.message;
        }
        out.fields.push(cell);
    }
    return out;
}

rpc.exports = {
    install: function(addrStr){
        TARGET = ptr(addrStr);
        Interceptor.attach(TARGET, {
            onEnter: function(args){
                const ecx = this.context.ecx;
                const dump = dumpSendTask(ecx);
                dump.tid = this.threadId;
                dump.ts = Date.now();
                dump.addr = addrStr;
                send({t:'hit', dump: dump});
            }
        });
        send({t:'installed', addr: addrStr});
        return true;
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


def print_dump_pretty(hit_idx: int, dump: dict[str, Any]) -> None:
    print()
    print(f"╔══════════════════════════════════════════════════════════════")
    print(f"║  HIT #{hit_idx}   this = {dump['this_addr']}   tid = {dump.get('tid')}")
    print(f"╚══════════════════════════════════════════════════════════════")
    for f in dump.get("fields") or []:
        off = f["off"]
        raw = f.get("raw", "?")
        segs = []
        if "cstr" in f:
            v = f["cstr"]
            segs.append(f"cstr={v[:80]!r}" + (" ..." if len(v) > 80 else ""))
        if "w" in f:
            v = f["w"]
            segs.append(f"utf16={v[:60]!r}" + (" ..." if len(v) > 60 else ""))
        if "std_string" in f:
            ss = f["std_string"]
            segs.append(f"std::string[{ss['mode']} sz={ss['size']} cap={ss['cap']}]={ss['val'][:80]!r}")
        if "std_vector" in f:
            vv = f["std_vector"]
            u32 = vv.get("as_u32") or []
            u64 = vv.get("as_u64") or []
            head = ""
            if u64 and len(u64) <= 8:
                head = " u64=[" + ", ".join(u64[:5]) + (", ..." if len(u64) > 5 else "") + "]"
            elif u32:
                head = " u32=[" + ", ".join(u32[:5]) + (", ..." if len(u32) > 5 else "") + "]"
            segs.append(f"std::vector[span={vv['span_bytes']}B]{head}")
        if not segs:
            # 只打印 raw 值（限制噪声）
            continue
        joined = "  ".join(segs)
        marker = " ⭐" if off == 0x64 else ("  " if off < 0x10 else "")
        print(f"  this+0x{off:02x}  raw={raw:12s}{marker}  {joined}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=str, default=DEFAULT_TARGET,
                    help=f"hook 目标地址（默认 {DEFAULT_TARGET}）")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--max-hits", type=int, default=6,
                    help="最多详细打印几条 hit（超过只写 ndjson）")
    args = ap.parse_args(argv)

    pid = args.pid or get_wxwork_pid()
    print(f"[*] attaching PID = {pid}, target = {args.target}")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ndjson_path = OUT_DIR / f"sendtask_dump_{ts}.ndjson"

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
                d = p["dump"]
                hits.append(d)
                fp.write(json.dumps(d, ensure_ascii=False) + "\n")
                fp.flush()
                if len(hits) <= args.max_hits:
                    print_dump_pretty(len(hits), d)
                else:
                    print(f"  [hit #{len(hits)}] written to ndjson only")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    script.exports_sync.install(args.target)
    print(f"[*] armed. Do forward(s) within {args.duration}s"
          f" (FTA→外部联系人效果最好，能看到 S: 前缀 conv_id)")

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        time.sleep(1)

    fp.close()
    print()
    print(f"[+] captured {len(hits)} hits → {ndjson_path.name}")
    print(f"[+] 检查 this+0x64 处是否为 std::string 且包含 'S:xxx_yyy'")
    print(f"    以及是否有 std::vector 字段（那就是 msg_ids）")

    try:
        script.unload(); session.detach()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
