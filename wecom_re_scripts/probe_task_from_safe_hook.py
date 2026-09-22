# probe_task_from_safe_hook.py — P2 · 从安全 hook 点找 PostSendMessageTask2 对象
# =============================================================================
#
# 第二十四轮静态分析结论：
#   PostSendMessageTask2 对象结构：
#     [this + 0x00] = vtable → 0xb52b210 (在 wxwork.exe .rdata)
#     [this + 0x30] = m_package_ptr (指向另一个堆对象)
#     [*(this+0x30) + 0x28] = std::string conversationId
#
#   Hook DoExecute 等核心方法会触发企微 anti-tamper 自杀，
#   所以改从**安全 hook 点** `0x8dd8202` 反向找 Task 对象。
#
# 本脚本目标（只 hook `0x8dd8202`，不动敏感函数）：
#   1. 每次 hit 时 dump 栈临时结构前 0x100 字节里所有堆指针
#   2. 对每个堆指针 P，读 [P+0..0x40] 检查 vtable 是否 = 0xb52b210
#   3. 若命中 → 读 [P+0x30] 得 package_ptr
#   4. 读 [package+0x28..0x50] (std::string 24字节) 提取 conv_id
#      - 若 size <= 15：SSO buffer 直接读明文
#      - 若 size >= 16：读 [package+0x28] 处 char* 指向的字符串
#   5. 输出结果，验证静态推断
#
# 用户配合：2-3 次 FTA→外部转发
# 用法：& Python311 runtime/wecom_re/probe_task_from_safe_hook.py --duration 90
# =============================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

# wxwork.exe 相对偏移
SAFE_HOOK_OFFSET = "0x846820e"   # 0x8dd8202 - 0x970000 (base 变化时自适应)
VTABLE_OFFSET    = "0xabbb210"   # 0xb52b210 - 0x970000

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const WXBASE = wx.base;
send({t:'info', msg: 'wx base=' + WXBASE});

const CONV_RE = /^(S:\d{10,20}_\d{10,20}|R:[\w:_-]{10,64}|G:[\w:_-]{10,64})/;

let VTABLE_ABS = 0;
let SAFE_ADDR = null;
let COUNT = 0;

function readU32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function readCStr(p, cap){ try { return p.readCString(cap || 128); } catch(e){ return null; } }

// 尝试从对象里读 std::string 内容
// std::string 32-bit MSVC 布局: [0..15]=SSO union, [0x10]=size, [0x14]=capacity
function readStdString(objBase){
    const size = readU32(objBase.add(0x10));
    const cap  = readU32(objBase.add(0x14));
    if (size === 0) return {size:0, cap:cap, str:''};
    // size <= 15 → SSO buffer, size >= 16 → heap ptr
    if (size <= 15){
        // SSO: read 16 bytes as string
        let bytes;
        try { bytes = new Uint8Array(objBase.readByteArray(16)); }
        catch(e){ return {size:size, cap:cap, err:'read sso failed'}; }
        let s = '';
        for (let i = 0; i < size && i < bytes.length; i++){
            const b = bytes[i];
            if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
            else s += '?';
        }
        return {size:size, cap:cap, sso:true, str:s};
    } else {
        const ptr_u32 = readU32(objBase);
        if (!ptr_u32) return {size:size, cap:cap, err:'null ptr'};
        const s = readCStr(ptr(ptr_u32), Math.min(size + 4, 256));
        return {size:size, cap:cap, sso:false, ptr:'0x'+ptr_u32.toString(16),
                str: s || ''};
    }
}

// 检查 objAddr 是不是 PostSendMessageTask2 (vtable 匹配)
function checkTaskObj(objAddr){
    const vt = readU32(ptr(objAddr));
    if (vt !== VTABLE_ABS) return null;
    // vtable 命中！读 [+0x30] = package_ptr
    const pkg = readU32(ptr(objAddr).add(0x30));
    if (!pkg || pkg < 0x10000){
        return {vt:'0x'+vt.toString(16), pkg:'null-or-invalid'};
    }
    // 读 [package + 0x28..0x50] 作为 std::string
    const convStr = readStdString(ptr(pkg).add(0x28));
    // 额外读 [package + 0x40] 等其他候选偏移（保险起见）
    const alt1 = readStdString(ptr(pkg).add(0x00));
    const alt2 = readStdString(ptr(pkg).add(0x10));
    const alt3 = readStdString(ptr(pkg).add(0x40));
    return {
        task_addr: '0x' + objAddr.toString(16),
        vt: '0x' + vt.toString(16),
        pkg: '0x' + pkg.toString(16),
        conv_at_0x28: convStr,
        alt_at_0x00: alt1,
        alt_at_0x10: alt2,
        alt_at_0x40: alt3
    };
}

// 扫 stack/heap 附近找指向 Task 对象的指针
function scanForTaskObj(ecx){
    const found = [];
    // 扫 ecx 前 0x100 字节
    for (let off = 0; off < 0x100; off += 4){
        const raw = readU32(ecx.add(off));
        if (!raw || raw < 0x100000) continue;
        // raw 可能指向 heap 对象或 wxwork 内存
        const info = checkTaskObj(raw);
        if (info){
            info.found_at = 'ecx+0x' + off.toString(16);
            found.push(info);
        }
        // 也检查 raw 指向的对象是否包含 Task 对象指针（一层间接）
        // 读 [raw + 0..0x60] 看是不是 Task 对象
        for (let inner = 0; inner < 0x60; inner += 4){
            const inner_raw = readU32(ptr(raw).add(inner));
            if (!inner_raw || inner_raw < 0x100000) continue;
            const info2 = checkTaskObj(inner_raw);
            if (info2){
                info2.found_at = 'ecx+0x' + off.toString(16) + '→[+0x' + inner.toString(16) + ']';
                found.push(info2);
            }
        }
    }
    return found;
}

rpc.exports = {
    install: function(safeOffsetStr, vtableOffsetStr){
        VTABLE_ABS = WXBASE.add(parseInt(vtableOffsetStr, 16)).toUInt32();
        SAFE_ADDR = WXBASE.add(parseInt(safeOffsetStr, 16));
        send({t:'info', msg: 'safe hook @ ' + SAFE_ADDR + ' vtable @ 0x' + VTABLE_ABS.toString(16)});
        Interceptor.attach(SAFE_ADDR, {
            onEnter: function(){
                COUNT++;
                if (COUNT > 20) return;  // 只报前 20 次
                const ecx = this.context.ecx;
                const results = scanForTaskObj(ecx);
                if (results.length === 0) return;
                send({t:'task_found',
                      seq: COUNT,
                      hook_ecx: ecx.toString(),
                      tid: this.threadId,
                      tasks: results});
            }
        });
    },
    stats: function(){ return {count: COUNT}; }
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=90)
    args = ap.parse_args(argv)

    pid = get_wxwork_pid()
    print(f"[*] attaching PID={pid}")

    import frida
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"probe_task_{ts}.ndjson"

    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    hits: list = []
    ready = {"v": False}
    fp = ndjson_path.open("a", encoding="utf-8")

    def on_message(msg: dict, data: Any) -> None:
        if msg.get("type") == "send":
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                ready["v"] = True
            elif t == "info":
                print(f"[+] {p['msg']}")
            elif t == "task_found":
                hits.append(p)
                fp.write(json.dumps(p, ensure_ascii=False) + "\n")
                fp.flush()
                print(f"\n[HIT #{p['seq']}] hook_ecx={p['hook_ecx']}  tid={p['tid']}")
                for t in p["tasks"]:
                    print(f"  ★ Task obj @ {t['task_addr']}  (found_at {t['found_at']})")
                    print(f"    vtable={t['vt']}  package={t['pkg']}")
                    conv = t.get("conv_at_0x28", {})
                    if conv.get("str"):
                        print(f"    → package+0x28 std::string: size={conv.get('size')} cap={conv.get('cap')} str={conv['str']!r}")
                    for key in ("alt_at_0x00", "alt_at_0x10", "alt_at_0x40"):
                        alt = t.get(key, {})
                        if alt.get("str"):
                            print(f"      {key}: size={alt.get('size')} str={alt['str']!r}")
        elif msg.get("type") == "error":
            print(f"[!] JS ERR: {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    script.exports_sync.install(SAFE_HOOK_OFFSET, VTABLE_OFFSET)
    print(f"\n[*] armed for {args.duration}s. 现在做 2-3 次 FTA→外部联系人 转发\n")

    deadline = time.monotonic() + args.duration
    while time.monotonic() < deadline:
        time.sleep(1)

    fp.close()
    st = script.exports_sync.stats()
    print(f"\n[+] final: safe-hook triggered {st['count']}x, task_found reports = {len(hits)}")
    print(f"[+] → {ndjson_path.name}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
