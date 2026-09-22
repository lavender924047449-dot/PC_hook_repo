# scan_task_readonly.py — P2 · 零 hook 只读扫堆，验证 conv_id 静态推断
# =============================================================================
#
# 第二十四轮结论（§40）：
#   PostSendMessageTask2 vtable @ wxbase + 0xabbb210
#   this + 0x30  = package_ptr
#   package + 0x28 = std::string conversationId
#
#   Hook PostSendMessageTask2 触发企微 anti-tamper。
#
# 本脚本目标（第二十五轮，方案 D）：
#   完全**不 hook 任何函数**。用 Windows API `ReadProcessMemory` 从外部进程
#   扫企微所有 rw 堆页，找 dword == vtable_va 的位置 → task 对象 → 沿字段路径
#   读 conv_id。
#
#   优先用 Frida attach + Process.enumerateRanges（性能好），失败则完全 fallback
#   到纯 Windows API（不 attach，零可探测痕迹）。
#
# 用户配合：企微在跑就行；用户做几次转发让 task 对象出现在堆里
# 用法：& Python311 runtime/wecom_re/scan_task_readonly.py [--mode frida|rpm]
# =============================================================================

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

VTABLE_OFFSET = 0xabbb210  # wxwork.exe + 0xabbb210 = PostSendMessageTask2 vtable
FIELD_PACKAGE_PTR = 0x30   # task->[0x30] = package pointer
FIELD_CONV_STRING = 0x28   # package->[0x28] = std::string conversationId


# ============================================================================
# Windows API path (方案 F fallback)
# ============================================================================

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

MEM_COMMIT = 0x1000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READONLY = 0x02
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE = 0x10
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


def open_process(pid: int, rw: bool = False) -> int:
    access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    if rw:
        access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    h = kernel32.OpenProcess(access, False, pid)
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def close_handle(h: int) -> None:
    kernel32.CloseHandle(h)


def get_wxwork_base(h: int) -> tuple[int, int]:
    """通过 EnumProcessModulesEx 找 wxwork.exe base + size。"""
    LIST_MODULES_ALL = 0x03
    hmods = (wintypes.HMODULE * 1024)()
    cb_needed = wintypes.DWORD()
    psapi.EnumProcessModulesEx(h, hmods, ctypes.sizeof(hmods),
                                ctypes.byref(cb_needed), LIST_MODULES_ALL)
    n = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
    for i in range(n):
        name_buf = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(h, hmods[i], name_buf, 260)
        if name_buf.value.lower() == "wxwork.exe":
            mi = MODULEINFO()
            psapi.GetModuleInformation(h, hmods[i], ctypes.byref(mi),
                                       ctypes.sizeof(mi))
            return mi.lpBaseOfDll, mi.SizeOfImage
    raise RuntimeError("wxwork.exe module not found")


def read_process_memory(h: int, addr: int, size: int) -> bytes | None:
    buf = (ctypes.c_ubyte * size)()
    n_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size,
                                    ctypes.byref(n_read))
    if not ok or n_read.value < size:
        return None
    return bytes(buf)


def enum_rw_regions(h: int) -> list[tuple[int, int]]:
    """列举所有可读的 rw 或 rwx 私有区域（堆）。"""
    regions = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < 0x7FFF0000:  # 32-bit user space upper
        r = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                                    ctypes.byref(mbi),
                                    ctypes.sizeof(mbi))
        if r == 0:
            break
        if mbi.State == MEM_COMMIT:
            prot = mbi.Protect & 0xff
            # 只关心 rw 私有堆（排除映射文件、guard page、noaccess）
            is_rw = prot in (PAGE_READWRITE, PAGE_EXECUTE_READWRITE)
            has_guard = mbi.Protect & PAGE_GUARD
            if is_rw and not has_guard and mbi.Type == MEM_PRIVATE:
                regions.append((mbi.BaseAddress or 0, mbi.RegionSize))
        addr = (mbi.BaseAddress or 0) + mbi.RegionSize
    return regions


def read_std_string(h: int, base: int) -> dict:
    """读 MSVC 32-bit std::string (24 字节结构): SSO union + size + capacity."""
    data = read_process_memory(h, base, 24)
    if not data or len(data) < 24:
        return {"err": "read failed"}
    ptr_or_sso = struct.unpack_from("<I", data, 0)[0]
    size = struct.unpack_from("<I", data, 0x10)[0]
    cap = struct.unpack_from("<I", data, 0x14)[0]
    if size == 0:
        return {"size": 0, "cap": cap, "str": ""}
    if size <= 15:
        # SSO: 前 16 字节就是明文
        try:
            s = data[0:min(size, 16)].decode("utf-8", errors="replace")
        except Exception:
            s = data[0:16].hex()
        return {"size": size, "cap": cap, "sso": True, "str": s}
    # heap ptr
    if not ptr_or_sso:
        return {"size": size, "cap": cap, "err": "null ptr"}
    heap_data = read_process_memory(h, ptr_or_sso, min(size + 4, 256))
    if not heap_data:
        return {"size": size, "cap": cap, "ptr": hex(ptr_or_sso), "err": "heap read failed"}
    s = heap_data[:size].decode("utf-8", errors="replace")
    return {"size": size, "cap": cap, "sso": False,
            "ptr": hex(ptr_or_sso), "str": s}


def scan_rpm_mode(pid: int) -> list[dict]:
    """方案 F: 纯 Windows API 扫描"""
    print(f"[F] using pure Windows API (no Frida attach)")
    h = open_process(pid, rw=False)
    print(f"[F] opened PID={pid} handle=0x{h:x}")

    wx_base, wx_size = get_wxwork_base(h)
    print(f"[F] wxwork.exe base=0x{wx_base:x}  size=0x{wx_size:x}")

    vtable_va = wx_base + VTABLE_OFFSET
    print(f"[F] target vtable VA = 0x{vtable_va:x}")

    regions = enum_rw_regions(h)
    total_bytes = sum(sz for _, sz in regions)
    print(f"[F] enumerated {len(regions)} rw regions, total {total_bytes / 1024 / 1024:.1f} MB")

    vt_bytes = struct.pack("<I", vtable_va)
    results = []
    t0 = time.monotonic()

    for base, size in regions:
        # 一次读一整段
        data = read_process_memory(h, base, size)
        if not data:
            continue
        # 扫 dword-aligned 位置
        off = 0
        while off + 4 <= len(data):
            if data[off:off + 4] == vt_bytes:
                task_addr = base + off
                # 读 task 前 0x100 字节
                task_data = read_process_memory(h, task_addr, 0x100)
                if not task_data or len(task_data) < 0x40:
                    off += 4
                    continue
                pkg_ptr = struct.unpack_from("<I", task_data, FIELD_PACKAGE_PTR)[0]
                info = {
                    "task_addr": hex(task_addr),
                    "vtable": hex(vtable_va),
                    "pkg_ptr": hex(pkg_ptr) if pkg_ptr else "null",
                    "task_first_dw": [hex(x) for x in struct.unpack_from("<16I", task_data, 0)],
                }
                if pkg_ptr and pkg_ptr >= 0x10000:
                    info["conv_string"] = read_std_string(h, pkg_ptr + FIELD_CONV_STRING)
                    # 也尝试其他候选 offsets 以防推断偏移
                    info["alt_at_0x00"] = read_std_string(h, pkg_ptr + 0x00)
                    info["alt_at_0x10"] = read_std_string(h, pkg_ptr + 0x10)
                    info["alt_at_0x40"] = read_std_string(h, pkg_ptr + 0x40)
                    info["alt_at_0x50"] = read_std_string(h, pkg_ptr + 0x50)
                results.append(info)
            off += 4

    dur = time.monotonic() - t0
    print(f"[F] scan done in {dur:.1f}s, found {len(results)} matches")
    close_handle(h)
    return results


# ============================================================================
# Frida mode (方案 D, 优先尝试)
# ============================================================================

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

function readStdString(base){
    const size = u32(base.add(0x10));
    const cap  = u32(base.add(0x14));
    if (size === 0) return {size:0, cap:cap, str:''};
    if (size <= 15){
        let bytes;
        try { bytes = new Uint8Array(base.readByteArray(16)); }
        catch(e){ return {size:size, cap:cap, err:'read sso failed'}; }
        let s = '';
        for (let i = 0; i < size && i < bytes.length; i++){
            const b = bytes[i];
            s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
        }
        return {size:size, cap:cap, sso:true, str:s};
    }
    const ptrU32 = u32(base);
    if (!ptrU32) return {size:size, cap:cap, err:'null ptr'};
    const s = readStr(ptr(ptrU32), Math.min(size + 4, 256));
    return {size:size, cap:cap, sso:false, ptr:'0x'+ptrU32.toString(16),
            str: s || ''};
}

rpc.exports = {
    scan: function(vtableOffsetStr){
        const vtVA = WXBASE.add(parseInt(vtableOffsetStr, 16)).toUInt32();
        send({t:'info', msg: 'target vtable VA = 0x' + vtVA.toString(16)});

        const results = [];
        const ranges = Process.enumerateRanges({protection: 'rw-', coalesce: false});
        let totalMB = 0;
        for (let i = 0; i < ranges.length; i++) totalMB += ranges[i].size;
        send({t:'info', msg: 'enumerated ' + ranges.length + ' rw ranges, ' +
             (totalMB/1024/1024).toFixed(1) + ' MB'});

        // 用 Memory.scan 找 vtable 4-byte pattern
        const vtBytes = [
            (vtVA & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 8) & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 16) & 0xff).toString(16).padStart(2, '0'),
            ((vtVA >>> 24) & 0xff).toString(16).padStart(2, '0')
        ].join(' ');

        for (let i = 0; i < ranges.length; i++){
            const r = ranges[i];
            try {
                const ms = Memory.scanSync(r.base, r.size, vtBytes);
                for (let j = 0; j < ms.length; j++){
                    const taskAddr = ms[j].address;
                    // 前 0x40 dwords
                    const dw = [];
                    for (let off = 0; off <= 0x40; off += 4){
                        dw.push('0x' + u32(taskAddr.add(off)).toString(16));
                    }
                    const pkgPtr = u32(taskAddr.add(0x30));
                    let convInfo = null;
                    let alts = {};
                    if (pkgPtr && pkgPtr >= 0x10000){
                        convInfo = readStdString(ptr(pkgPtr).add(0x28));
                        alts = {
                            at_0x00: readStdString(ptr(pkgPtr).add(0x00)),
                            at_0x10: readStdString(ptr(pkgPtr).add(0x10)),
                            at_0x40: readStdString(ptr(pkgPtr).add(0x40)),
                            at_0x50: readStdString(ptr(pkgPtr).add(0x50)),
                        };
                    }
                    results.push({
                        task_addr: taskAddr.toString(),
                        pkg_ptr: pkgPtr ? '0x'+pkgPtr.toString(16) : 'null',
                        task_first_dw: dw,
                        conv_string: convInfo,
                        alts: alts
                    });
                }
            } catch(e){}
        }
        return results;
    }
};
send({t:'ready'});
"""


def scan_frida_mode(pid: int) -> list[dict]:
    """方案 D: Frida attach + Process.enumerateRanges 扫描（不 hook 任何函数）"""
    print(f"[D] using Frida read-only scan (no hooks)")
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

    print(f"[D] scanning heap...")
    t0 = time.monotonic()
    results = script.exports_sync.scan(hex(VTABLE_OFFSET))
    print(f"[D] scan done in {time.monotonic()-t0:.1f}s, found {len(results)} matches")

    try: script.unload(); session.detach()
    except Exception: pass
    return results


def scan_frida_loop(pid: int, duration: int, interval_ms: int = 200) -> list[dict]:
    """持续 loop 扫描，抓短暂存活的 task 对象。"""
    print(f"[D-loop] Frida read-only, loop for {duration}s, interval={interval_ms}ms")
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

    seen_tasks: set = set()
    all_results = []
    deadline = time.monotonic() + duration
    scan_count = 0
    print(f"[D-loop] 现在做 2-3 次 FTA→外部转发，脚本每 {interval_ms}ms 扫一次...")
    while time.monotonic() < deadline:
        scan_count += 1
        try:
            results = script.exports_sync.scan(hex(VTABLE_OFFSET))
        except Exception as e:
            print(f"[!] scan #{scan_count} failed: {e}")
            break
        if results:
            new_ones = [r for r in results if r["task_addr"] not in seen_tasks]
            for r in new_ones:
                seen_tasks.add(r["task_addr"])
                all_results.append(r)
                conv = r.get("conv_string") or {}
                print(f"\n[#{scan_count} @ t+{time.monotonic() - (deadline - duration):.1f}s]")
                print(f"  ★ Task @ {r['task_addr']}  pkg={r['pkg_ptr']}")
                if conv.get("str"):
                    print(f"    → package+0x28: size={conv.get('size')} "
                          f"sso={conv.get('sso')} str={conv.get('str')!r}")
                else:
                    # 尝试 alts
                    alts = r.get("alts", {})
                    found_any = False
                    for k, v in alts.items():
                        if v and v.get("str") and str(v.get("str")).startswith(("S:", "R:", "G:", "1", "2", "3", "4", "5", "6", "7", "8", "9")):
                            print(f"    → package+{k}: size={v.get('size')} str={v.get('str')!r}")
                            found_any = True
                    if not found_any:
                        print(f"    (no conv at 0x28; task_dw[6..12]={r['task_first_dw'][6:13]})")
        time.sleep(interval_ms / 1000.0)

    print(f"\n[D-loop] {scan_count} scans done, {len(all_results)} unique task objects")
    try: script.unload(); session.detach()
    except Exception: pass
    return all_results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--mode", choices=["frida", "frida-loop", "rpm", "auto"], default="frida-loop")
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--interval-ms", type=int, default=200)
    args = ap.parse_args(argv)

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

    results = []
    if args.mode == "frida-loop":
        results = scan_frida_loop(pid, args.duration, args.interval_ms)
    elif args.mode in ("frida", "auto"):
        try:
            results = scan_frida_mode(pid)
        except Exception as e:
            print(f"[!] Frida mode failed: {e}")
            if args.mode == "auto":
                print("[*] falling back to RPM mode...")
                results = scan_rpm_mode(pid)
    else:
        results = scan_rpm_mode(pid)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUT_DIR / f"scan_task_readonly_{ts}.json"
    out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2),
                        encoding="utf-8")

    # 展示
    print()
    print("=" * 80)
    print(f"[+] {len(results)} task obj(s) found")
    # 过滤 conv_string 非空的
    with_conv = [r for r in results if r.get("conv_string")
                 and (r["conv_string"].get("str") or "").startswith(("S:", "R:", "G:"))]
    print(f"[+] {len(with_conv)} with valid conv_id at package+0x28")
    for r in with_conv[:10]:
        conv = r["conv_string"]
        print(f"\n  Task @ {r['task_addr']}  package={r['pkg_ptr']}")
        print(f"    → conv_string: size={conv.get('size')} sso={conv.get('sso')} str={conv.get('str')!r}")

    if not with_conv and results:
        # 静态推断可能错，扫其他 offsets
        print(f"\n  [!] 0x28 处没找到 conv_id，检查 alt offsets：")
        for r in results[:5]:
            print(f"  Task @ {r['task_addr']}  package={r['pkg_ptr']}")
            alts = r.get("alts", {})
            for k, v in alts.items():
                if v and v.get("str"):
                    print(f"    {k}: size={v.get('size')} str={v.get('str')!r}")

    print(f"\n[+] → {out_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
