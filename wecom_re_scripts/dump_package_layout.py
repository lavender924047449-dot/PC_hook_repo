# dump_package_layout.py — M1 · 逆向 PostSendMessageTask2 package 完整字节布局
# =============================================================================
#
# 目标：既然已知 package+0x28 = std::string(conversationId)，那么 package 里其他
# 关键字段（content_type / resource_ref / duration / silk_md5 / media_id / ...）
# 到底躺在哪个 offset？—— diff 不同类型消息的 package 就能找出来。
#
# 用户配合流程：
#   一次会话内，按 --type 参数标记的顺序，依次发几条不同类型的消息给 FTA。
#   比如：
#     - `--type text`   → 发一条 "test1" 文字
#     - `--type image`  → 发一张小图
#     - `--type voice`  → 按住说话录一段 "test voice"
#     - `--type video`  → 发一段短视频
#     - `--type file`   → 发一个小文件
#
#   每一轮跑一次本脚本、跑完自动落盘一个 JSON。之后跑 diff_package_layout.py
#   对比不同类型 package 的字节差异，一眼看出 content_type 字段等。
#
# 严格约束（§40 / §41.8）：
#   * 只用 Frida read-only + Memory.scanSync + readByteArray
#   * 禁止 Interceptor.attach / .replace（企微 anti-tamper 会自杀）
#   * 禁止写内存（本脚本是 dump，不改）
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

FIELD_PACKAGE_PTR = 0x30

TASK_DUMP_BYTES = 0x100
PACKAGE_DUMP_BYTES = 0x300

# 企微 5.0.10.6015 · 已知 Task vtable RVA
KNOWN_VTABLES: dict[str, int] = {
    "PostSendMessageTask2": 0xABBB210,
    "HandleMessageResourcesTask": 0xABBACC4,
    "HandleForwardResourcesTask2": 0xABBA8C8,
}

# voice 走资源上传 + 发送双链路，三种 vtable 都要扫
VTABLES_BY_TYPE: dict[str, list[str]] = {
    "voice": [
        "PostSendMessageTask2",
        "HandleMessageResourcesTask",
        "HandleForwardResourcesTask2",
    ],
}

MSG_TYPES = ("text", "image", "voice", "video", "file",
             "miniprogram", "sticker", "location", "card", "video_channel")


FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base;
send({t:'info', msg:'wx base=' + WXBASE});

const TASK_DUMP = __TASK_DUMP__;
const PACKAGE_DUMP = __PACKAGE_DUMP__;

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function b2hex(bytes){
    if (!bytes) return '';
    const u = new Uint8Array(bytes);
    const s = [];
    for (let i = 0; i < u.length; i++)
        s.push(u[i].toString(16).padStart(2, '0'));
    return s.join('');
}
function isReadable(p, len){
    try { p.readByteArray(len); return true; }
    catch(e){ return false; }
}

/* Interpret MSVC 32-bit std::string at `base`.
   Returns {kind:'sso'|'heap'|'empty'|'invalid', size, cap, str_utf8?} */
function tryStdString(base){
    let ptrOrSso, size, cap;
    try {
        ptrOrSso = u32(base);
        size = u32(base.add(0x10));
        cap  = u32(base.add(0x14));
    } catch(e){ return null; }
    // Basic sanity: cap must be >= size, size < 64KB, cap < 4MB
    if (size > 0x10000) return null;
    if (cap  > 0x400000) return null;
    if (cap  < size) return null;
    if (size === 0){
        if (cap === 0 || cap === 15) return {kind:'empty', size:0, cap:cap, str_utf8:''};
        return null;
    }
    if (size <= 15){
        // SSO
        let bytes;
        try { bytes = new Uint8Array(base.readByteArray(16)); }
        catch(e){ return null; }
        // Must be printable-ish or valid UTF-8 first byte
        let printable = 0;
        for (let i = 0; i < size; i++){
            const b = bytes[i];
            if ((b >= 0x20 && b <= 0x7e) || b >= 0x80) printable++;
        }
        if (printable < size) return null;
        // Decode as UTF-8
        let s = '';
        for (let i = 0; i < size; i++) s += String.fromCharCode(bytes[i]);
        return {kind:'sso', size:size, cap:cap, str_utf8:s,
                str_hex: b2hex(base.readByteArray(size))};
    }
    // Heap: ptrOrSso must point to readable
    if (ptrOrSso < 0x10000) return null;
    if (!isReadable(ptr(ptrOrSso), size)) return null;
    const bytes = ptr(ptrOrSso).readByteArray(size);
    let s = '';
    try {
        const u = new Uint8Array(bytes);
        for (let i = 0; i < u.length; i++){
            const b = u[i];
            if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) s += '?';
            else if (b <= 0x7e) s += String.fromCharCode(b);
            else s += '?';
        }
    } catch(e){}
    return {kind:'heap', size:size, cap:cap,
            ptr:'0x'+ptrOrSso.toString(16),
            str_utf8:s, str_hex: b2hex(bytes)};
}

/* Scan all 4-byte aligned offsets in [base, base+len) as std::string candidates,
   return only meaningful ones (non-empty and size>1 or valid empty). */
function scanStringCandidates(base, len){
    const out = [];
    for (let off = 0; off + 0x18 <= len; off += 4){
        const s = tryStdString(base.add(off));
        if (s && s.kind !== 'empty' && s.size >= 1) out.push({off:'0x'+off.toString(16), ...s});
    }
    return out;
}

/* Read a raw block, return hex string. */
function readRaw(base, len){
    try { return b2hex(base.readByteArray(len)); }
    catch(e){ return null; }
}

/* Extract dword array (interpreted as u32 + hint 'ptr'|'int'|'size') */
function readDwords(base, len){
    const out = [];
    for (let off = 0; off < len; off += 4){
        let v;
        try { v = u32(base.add(off)); } catch(e){ v = 0; }
        // Heuristic hint
        let hint = 'int';
        if (v >= 0x10000 && v < 0x80000000){
            // Might be a pointer
            if (isReadable(ptr(v), 4)) hint = 'ptr';
        }
        out.push({off:'0x'+off.toString(16), u32:v, hex:'0x'+v.toString(16), hint:hint});
    }
    return out;
}

function vtBytesFromRva(rva){
    const vtVA = WXBASE.add(rva).toUInt32();
    return [
        (vtVA & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 8) & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 16) & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 24) & 0xff).toString(16).padStart(2, '0')
    ].join(' ');
}

function dumpTaskHit(taskAddr, className, vtableRva){
    const rec = {
        task_addr: taskAddr.toString(),
        class_name: className,
        vtable_rva: '0x' + vtableRva.toString(16),
        task_hex: readRaw(taskAddr, TASK_DUMP),
        task_dwords: readDwords(taskAddr, TASK_DUMP),
        task_strings: scanStringCandidates(taskAddr, TASK_DUMP),
        pkg_ptr: 'null',
    };
    const pkgPtr = u32(taskAddr.add(0x30));
    rec.pkg_ptr = pkgPtr ? '0x' + pkgPtr.toString(16) : 'null';
    if (pkgPtr && pkgPtr >= 0x10000 && isReadable(ptr(pkgPtr), PACKAGE_DUMP)){
        const pkg = ptr(pkgPtr);
        rec.pkg_hex = readRaw(pkg, PACKAGE_DUMP);
        rec.pkg_dwords = readDwords(pkg, PACKAGE_DUMP);
        rec.pkg_strings = scanStringCandidates(pkg, PACKAGE_DUMP);
    }
    return rec;
}

rpc.exports = {
    /* 在 JS 内 tight loop，避免 Python 往返拖慢扫描 */
    scanLoop: function(specJson, durationMs){
        const spec = JSON.parse(specJson);
        const targets = spec.targets;  // [{name,rva}, ...]
        const patterns = [];
        for (let i = 0; i < targets.length; i++){
            patterns.push({
                name: targets[i].name,
                rva: targets[i].rva,
                bytes: vtBytesFromRva(targets[i].rva),
            });
        }
        const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        const seen = {};
        const events = [];
        let scans = 0;
        const t0 = Date.now();
        const deadline = t0 + durationMs;
        while (Date.now() < deadline){
            scans++;
            for (let p = 0; p < patterns.length; p++){
                const pat = patterns[p];
                for (let i = 0; i < ranges.length; i++){
                    const r = ranges[i];
                    let ms;
                    try { ms = Memory.scanSync(r.base, r.size, pat.bytes); }
                    catch(e){ continue; }
                    for (let j = 0; j < ms.length; j++){
                        const taskAddr = ms[j].address;
                        const key = pat.name + '@' + taskAddr.toString();
                        if (seen[key]) continue;
                        const rec = dumpTaskHit(taskAddr, pat.name, pat.rva);
                        seen[key] = rec;
                        events.push({
                            t_ms: Date.now() - t0,
                            scan: scans,
                            class_name: pat.name,
                            task_addr: rec.task_addr,
                            pkg_ptr: rec.pkg_ptr,
                            n_task_strings: (rec.task_strings || []).length,
                            n_pkg_strings: (rec.pkg_strings || []).length,
                        });
                    }
                }
            }
        }
        const tasks = [];
        for (const k in seen) tasks.push(seen[k]);
        return {
            scans: scans,
            duration_ms: Date.now() - t0,
            tasks: tasks,
            events: events,
        };
    }
};
send({t:'ready'});
"""


def _find_wxwork_pid() -> int | None:
    r = subprocess.run(
        ["powershell", "-Command",
         "Get-Process WXWork -ErrorAction SilentlyContinue | "
         "Sort-Object WorkingSet64 -Descending | "
         "Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True, encoding="utf-8",
    )
    s = r.stdout.strip()
    return int(s) if s else None


def _resolve_vtables(msg_type: str, extra: list[str] | None) -> list[dict[str, Any]]:
    names = VTABLES_BY_TYPE.get(msg_type, ["PostSendMessageTask2"])
    if extra:
        names = extra
    out: list[dict[str, Any]] = []
    for name in names:
        rva = KNOWN_VTABLES.get(name)
        if rva is None:
            raise ValueError(f"unknown vtable class: {name}")
        out.append({"name": name, "rva": rva})
    return out


def dump_loop(
    pid: int,
    msg_type: str,
    duration: int,
    vtables: list[dict[str, Any]],
) -> dict:
    """在 JS 内 tight loop 扫堆 duration 秒，把每个唯一 task 存下来。"""
    vt_desc = ", ".join(f"{v['name']}=0x{v['rva']:x}" for v in vtables)
    print(f"[*] dumping tasks, msg_type={msg_type}, duration={duration}s")
    print(f"[*] vtables: {vt_desc}")
    import frida  # 延迟 import 便于测试
    session = frida.get_local_device().attach(pid)
    js = (FRIDA_JS
          .replace("__TASK_DUMP__", str(TASK_DUMP_BYTES))
          .replace("__PACKAGE_DUMP__", str(PACKAGE_DUMP_BYTES)))
    script = session.create_script(js)
    ready = {"v": False}

    def on_message(msg, _data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "info":
                print(f"    [js] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)

    print(f"[*] 现在配合发一条 {msg_type} 消息给 FTA（JS 内连续扫堆，无 Python 往返）...")
    if msg_type == "voice":
        print("[i] 语音：按住说话 15-20 秒，松开后等脚本跑完")
    t_start = time.monotonic()
    spec = json.dumps({"targets": vtables})
    try:
        result = script.exports_sync.scan_loop(spec, duration * 1000)
    except Exception as e:
        print(f"[!] scan_loop failed: {e}")
        result = {"scans": 0, "duration_ms": 0, "tasks": [], "events": []}

    for ev in result.get("events") or []:
        print(f"  [+{ev.get('t_ms', 0)/1000:5.1f}s scan#{ev.get('scan')} "
              f"{ev.get('class_name')} @{ev.get('task_addr')} "
              f"pkg={ev.get('pkg_ptr')} "
              f"task_str={ev.get('n_task_strings')} pkg_str={ev.get('n_pkg_strings')}")

    try:
        script.unload(); session.detach()
    except Exception:
        pass

    scans = int(result.get("scans") or 0)
    js_ms = int(result.get("duration_ms") or 0)
    if js_ms > 0:
        print(f"[*] JS loop: {scans} scans in {js_ms/1000:.1f}s "
              f"(~{scans/(js_ms/1000):.1f} scans/s)")

    return {
        "msg_type": msg_type,
        "pid": pid,
        "vtables": [{"name": v["name"], "rva": hex(v["rva"])} for v in vtables],
        "duration_sec": time.monotonic() - t_start,
        "scans": scans,
        "scan_rate_per_sec": round(scans / max(js_ms / 1000, 0.001), 2),
        "task_dump_bytes": TASK_DUMP_BYTES,
        "package_dump_bytes": PACKAGE_DUMP_BYTES,
        "tasks": result.get("tasks") or [],
        "events": result.get("events") or [],
    }


def _pick_conv(rec: dict) -> str:
    """给 loop 里的进度输出用：找 package+0x28 处的字符串。"""
    for s in rec.get("pkg_strings") or []:
        if s.get("off") == "0x28":
            return s.get("str_utf8") or ""
    return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="dump wework Task objects by vtable")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--type", choices=MSG_TYPES, required=True,
                    help="本轮要发的消息类型（会写入输出文件名）")
    ap.add_argument("--duration", type=int, default=60,
                    help="扫堆总时长，秒（默认 60）")
    ap.add_argument(
        "--vtable", action="append", default=None,
        help="额外/覆盖 vtable 类名，可重复。例: --vtable HandleMessageResourcesTask",
    )
    args = ap.parse_args(argv)

    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe running")
        return 1
    print(f"[*] target PID={pid}")

    vtables = _resolve_vtables(args.type, args.vtable)
    result = dump_loop(pid, args.type, args.duration, vtables)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUT_DIR / f"pkg_layout_{args.type}_{ts}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                        encoding="utf-8")

    print()
    print("=" * 70)
    tasks = result["tasks"]
    print(f"[+] {len(tasks)} unique task obj(s)  "
          f"({result.get('scans')} scans, {result.get('scan_rate_per_sec')} scans/s)")
    by_class: dict[str, list] = {}
    for t in tasks:
        by_class.setdefault(t.get("class_name") or "?", []).append(t)
    for cls, items in sorted(by_class.items()):
        print(f"    {cls}: {len(items)}")
    with_conv = [t for t in tasks if _pick_conv(t)]
    print(f"[+] {len(with_conv)} with conv_id at package+0x28")
    for t in tasks[:8]:
        conv = _pick_conv(t)
        n_ts = len(t.get("task_strings") or [])
        n_ps = len(t.get("pkg_strings") or [])
        print(f"  {t.get('class_name')} @{t['task_addr']} pkg={t.get('pkg_ptr')} "
              f"conv={conv!r} task_str={n_ts} pkg_str={n_ps}")
    print(f"\n[+] → {out_path.name}")
    print(f"[i] 下一步：跑不同 --type 各一次，然后 diff_package_layout.py 找类型差异")
    return 0


if __name__ == "__main__":
    sys.exit(main())
