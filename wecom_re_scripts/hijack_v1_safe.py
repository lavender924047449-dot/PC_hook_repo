# hijack_v1_safe.py — P2 · 只读扫堆 + heap 数据覆写 hijack（安全验证版）
# =============================================================================
#
# 第二十五轮验证：只读扫堆能拿到活着的 task 对象（scan_task_readonly.py）
#   task = 0x3252f9a8, package = 0x349c3528,
#   package+0x28 = std::string(size=35, str='S:1688855042791155_7881300363276969')
#
# 本脚本目标：
#   1. Loop-scan 找 PostSendMessageTask2 (vtable=wxbase+0xabbb210)
#   2. 读 [task+0x30] = package, 读 [package+0x28..] = std::string
#   3. 如果 conv_id == 原联系人 (7881300363276969)：
#      → 覆写 heap 上的字符串，把尾部 uin 改成 9999999999999999
#      （同长度 35，不动 std::string 元信息 size/cap/ptr）
#   4. 观察：原联系人还能不能收到（应该收不到，若 hijack 生效）
#
# 关键：完全不 hook 任何函数，只有 Memory.writeByteArray（写 heap 数据段，
# 企微 anti-tamper 通常不检测 heap 数据）
#
# 用户操作：转发一次到原联系人，看该联系人是否真的收到消息
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

VTABLE_OFFSET = 0xabbb210
FIELD_PACKAGE_PTR = 0x30
FIELD_CONV_STRING = 0x28

# 原联系人 conv_id（第二十五轮扫堆确认）—— 转发操作实际发给的人
DEFAULT_ORIGINAL_CONV_ID = "S:1688855042791155_7881300363276969"

# hijack 目标：改成不存在的 uin（safe）或另一个真实联系人（v2 重定向验证）
DEFAULT_HIJACK_CONV_ID = "S:1688855042791155_9999999999999999"

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('WXWork.exe not loaded');
const WXBASE = wx.base;
send({t:'info', msg: 'wx base=' + WXBASE});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function readStr(p, cap){ try { return p.readCString(cap || 128); } catch(e){ return null; } }

function bytesToAscii(bytes, size){
    let s = '';
    for (let i = 0; i < size && i < bytes.length; i++){
        const b = bytes[i];
        s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
    }
    return s;
}

function readStdString(base){
    const size = u32(base.add(0x10));
    const cap  = u32(base.add(0x14));
    if (size === 0) return {size:0, cap:cap, str:''};
    if (size <= 15){
        let bytes;
        try { bytes = new Uint8Array(base.readByteArray(16)); }
        catch(e){ return {size:size, cap:cap, err:'read sso failed'}; }
        return {size:size, cap:cap, sso:true, str:bytesToAscii(bytes, size), at: base.toString()};
    }
    const ptrU32 = u32(base);
    if (!ptrU32) return {size:size, cap:cap, err:'null ptr'};
    // 只读精确 size 字节（std::string 内部不保证 null-terminated）
    let bytes;
    try { bytes = new Uint8Array(ptr(ptrU32).readByteArray(size)); }
    catch(e){ return {size:size, cap:cap, err:'heap read failed'}; }
    return {size:size, cap:cap, sso:false, ptr:'0x'+ptrU32.toString(16),
            str: bytesToAscii(bytes, size), at: base.toString()};
}

rpc.exports = {
    scanTasks: function(vtableOffsetStr){
        const vtVA = WXBASE.add(parseInt(vtableOffsetStr, 16)).toUInt32();
        const vtBytes = [
            (vtVA & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 8) & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 16) & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 24) & 0xff).toString(16).padStart(2, '0')
        ].join(' ');
        const results = [];
        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: false});
        for (let i = 0; i < ranges.length; i++){
            const r = ranges[i];
            try {
                const ms = Memory.scanSync(r.base, r.size, vtBytes);
                for (let j = 0; j < ms.length; j++){
                    const taskAddr = ms[j].address;
                    const pkgPtr = u32(taskAddr.add(0x30));
                    if (!pkgPtr || pkgPtr < 0x10000) continue;
                    const convInfo = readStdString(ptr(pkgPtr).add(0x28));
                    results.push({
                        task_addr: taskAddr.toString(),
                        pkg_ptr: '0x'+pkgPtr.toString(16),
                        conv_string: convInfo,
                        // std::string 起始地址（用于后续覆写元信息，虽然本脚本不改）
                        string_obj_addr: ptr(pkgPtr).add(0x28).toString()
                    });
                }
            } catch(e){}
        }
        return results;
    },

    patchConvIdHeap: function(charPtrHex, newStr){
        // 覆写 heap 上的字符串数据（不动 std::string 元信息）
        const p = ptr(charPtrHex);
        try {
            const arr = new Uint8Array(newStr.length + 1);
            for (let i = 0; i < newStr.length; i++) arr[i] = newStr.charCodeAt(i);
            arr[newStr.length] = 0;  // null terminator
            // Frida 17: 使用 NativePointer.writeByteArray
            p.writeByteArray(arr.buffer);
            // 立即读回验证（读 size 字节，不用 CString）
            const verifyArr = new Uint8Array(p.readByteArray(newStr.length));
            let verify = '';
            for (let i = 0; i < verifyArr.length; i++){
                const b = verifyArr[i];
                verify += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
            }
            return {ok: true, verify: verify};
        } catch(e){
            return {ok: false, err: e.message + ' | stack=' + (e.stack || '')};
        }
    }
};
send({t:'ready'});
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--interval-ms", type=int, default=200)
    ap.add_argument("--dry-run", action="store_true", help="只扫，不改")
    ap.add_argument("--from-conv", default=DEFAULT_ORIGINAL_CONV_ID, help="原 conv_id（匹配到就 hijack）")
    ap.add_argument("--to-conv", default=DEFAULT_HIJACK_CONV_ID, help="hijack 到的新 conv_id（同长度）")
    args = ap.parse_args(argv)
    original_conv_id = args.from_conv
    hijack_conv_id = args.to_conv
    assert len(original_conv_id) == len(hijack_conv_id), \
        f"长度必须相同: from={len(original_conv_id)} to={len(hijack_conv_id)}"

    # 找 PID
    if args.pid:
        pid = args.pid
    else:
        r = subprocess.run(["powershell", "-Command",
                            "Get-Process WXWork -ErrorAction SilentlyContinue | "
                            "Sort-Object WorkingSet64 -Descending | "
                            "Select-Object -First 1 -ExpandProperty Id"],
                           capture_output=True, text=True, encoding="utf-8")
        pid_s = r.stdout.strip()
        if not pid_s:
            print("[!] no WXWork.exe running")
            return 1
        pid = int(pid_s)
    print(f"[*] target PID={pid}")
    print(f"[*] original conv_id  = {original_conv_id!r}")
    print(f"[*] hijack target     = {hijack_conv_id!r}")
    if args.dry_run:
        print(f"[*] DRY-RUN MODE (no write)")

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "info":
                print(f"    [D] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ndjson_path = OUT_DIR / f"hijack_v1_{ts}.ndjson"
    fp = ndjson_path.open("a", encoding="utf-8")

    patched: set = set()
    all_seen: set = set()
    events: list[dict] = []
    scan_count = 0
    deadline = time.monotonic() + args.duration
    print(f"\n[*] armed for {args.duration}s. 现在做 1 次 FTA→外部转发（用户端观察是否收到）\n")

    while time.monotonic() < deadline:
        scan_count += 1
        try:
            tasks = script.exports_sync.scan_tasks(hex(VTABLE_OFFSET))
        except Exception as e:
            print(f"[!] scan #{scan_count} failed: {e}")
            break
        for t in tasks:
            addr = t["task_addr"]
            conv = t.get("conv_string") or {}
            conv_str = conv.get("str", "")
            # 匹配原联系人
            if addr in all_seen:
                # 已见过，检查是否变化
                continue
            all_seen.add(addr)
            elapsed = time.monotonic() - (deadline - args.duration)
            event = {"scan": scan_count, "elapsed": round(elapsed, 2), "phase": "seen",
                     "task": addr, "pkg": t["pkg_ptr"],
                     "conv_addr": conv.get("at"), "conv_ptr": conv.get("ptr"),
                     "size": conv.get("size"), "str": conv_str}
            events.append(event)
            fp.write(json.dumps(event, ensure_ascii=False) + "\n")
            fp.flush()
            print(f"\n[t+{elapsed:.2f}s scan#{scan_count}] Task @ {addr}  pkg={t['pkg_ptr']}")
            print(f"  conv_string @ {conv.get('at')}  size={conv.get('size')}  ptr={conv.get('ptr')}")
            print(f"  str = {conv_str!r}")

            if conv_str != original_conv_id:
                print(f"  ⚠ conv_id 不是 target ({original_conv_id!r})，跳过")
                continue

            if args.dry_run:
                print(f"  [DRY] would hijack heap@{conv.get('ptr')} to {hijack_conv_id!r}")
                continue

            # HIJACK: 覆写 heap 上的字符串
            char_ptr = conv.get("ptr")
            if not char_ptr:
                print(f"  ❌ no heap ptr")
                continue
            print(f"  🚀 HIJACKING: writing new conv_id to heap@{char_ptr}")
            res = script.exports_sync.patch_conv_id_heap(char_ptr, hijack_conv_id)
            if res.get("ok"):
                patched.add(addr)
                event2 = {"scan": scan_count, "elapsed": round(elapsed, 2),
                          "phase": "patched", "task": addr,
                          "new_str": hijack_conv_id, "verify": res.get("verify")}
                events.append(event2)
                fp.write(json.dumps(event2, ensure_ascii=False) + "\n")
                fp.flush()
                print(f"  ✅ patched! verify read = {res.get('verify')!r}")
            else:
                print(f"  ❌ patch failed: {res.get('err')}")
        time.sleep(args.interval_ms / 1000.0)

    fp.close()
    print(f"\n{'='*80}")
    print(f"[+] {scan_count} scans, {len(all_seen)} unique tasks seen, {len(patched)} patched")
    print(f"[+] → {ndjson_path.name}")
    orig_uin = original_conv_id.split("_")[-1] if "_" in original_conv_id else original_conv_id
    hij_uin = hijack_conv_id.split("_")[-1] if "_" in hijack_conv_id else hijack_conv_id
    print(f"\n[!] 请检查：")
    print(f"    原联系人（uin={orig_uin}）：应该 没收到")
    print(f"    hijack 目标（uin={hij_uin}）：应该 收到")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
