# scan_all_class_names.py — M1b 补丁 · 扫 wxwork.exe 全部 MSVC C++ 类名
# =============================================================================
#
# 背景：wework_classes_all.txt 只包含 276 个 wework::logic Task 类（上次
# 扫描关键字仅匹配 "class wework::logic"）。语音/文件/视频的 Upload/Post 类
# 大概率在别的命名空间（wework::network / wework::media / 匿名 ns）。
#
# 本脚本：全量扫 .?AV / .?AU 前缀（MSVC RTTI 类型描述符 name 字段前缀），
# 落盘所有类名 + 对应 TypeDescriptor VA。之后 grep Voice/Audio/Upload 就有了。
#
# 只读扫 wxwork.exe 的 .data / .rdata 段（TypeDescriptor 通常在 .data）。
# 严格约束：不 hook，只扫内存。
# =============================================================================

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"


FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base;
const WXSIZE = wx.size;
send({t:'info', msg:'wx base=' + WXBASE + ' size=0x' + WXSIZE.toString(16)});

function safeCstr(p, cap){ try { return p.readCString(cap || 512); } catch(e){ return null; } }

rpc.exports = {
    scanAll: function(){
        // 扫 ".?AV" (V=class) 和 ".?AU" (U=struct) 两种 MSVC RTTI 前缀
        const patterns = ['2e 3f 41 56', '2e 3f 41 55'];  // .?AV / .?AU
        const found = {};  // TD_VA_hex → mangled name

        // 遍历 wxwork 模块内所有段
        const ranges = Process.enumerateRangesOfMalloc ?
            [] : Process.enumerateRanges({protection:'r--', coalesce:false});
        // 直接扫整个 wxwork
        for (let p = 0; p < patterns.length; p++){
            let hits;
            try {
                hits = Memory.scanSync(WXBASE, WXSIZE, patterns[p]);
            } catch(e){ continue; }
            for (let i = 0; i < hits.length; i++){
                const addr = hits[i].address;
                const s = safeCstr(addr, 512);
                if (!s) continue;
                if (s.length < 6) continue;
                // TypeDescriptor.name 起点是 +8，所以类字符串本身在 addr（作为
                // TypeDescriptor 的话，TD = addr - 8）。我们记录 name-VA 就够。
                found[addr.toString()] = s;
            }
        }
        return found;
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


def demangle_msvc(mangled: str) -> str:
    if not mangled or not mangled.startswith(".?A"):
        return mangled or ""
    body = mangled[4:] if mangled.startswith((".?AV", ".?AU")) else mangled[3:]
    if body.endswith("@@"):
        body = body[:-2]
    parts = [p for p in body.split("@") if p]
    if not parts: return mangled
    return "::".join(reversed(parts))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--grep", nargs="*", default=None,
                    help="只显示名字包含任一关键字的类（大小写不敏感）")
    args = ap.parse_args(argv)

    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe running"); return 1
    print(f"[*] target PID={pid}")

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}
    def on_msg(msg, _d):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready": ready["v"] = True
            elif p.get("t") == "info": print(f"    [js] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")
    script.on("message", on_msg)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    print(f"[*] scanning wxwork.exe for MSVC RTTI class names (.?AV / .?AU)...")
    t0 = time.monotonic()
    found: dict[str, str] = script.exports_sync.scan_all()
    print(f"[+] found {len(found)} class names in {time.monotonic()-t0:.1f}s")

    # 落盘全量
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    all_path = OUT_DIR / f"all_class_names_{ts}.json"
    all_path.write_text(json.dumps(found, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"[+] → {all_path.name}")

    # 展示：整合去重（同名类可能多次出现）
    unique_names: dict[str, list[str]] = {}
    for name_va, mangled in found.items():
        demangled = demangle_msvc(mangled)
        if demangled not in unique_names:
            unique_names[demangled] = []
        unique_names[demangled].append(name_va)

    print(f"[+] {len(unique_names)} unique demangled names")

    if args.grep:
        keys = [k.lower() for k in args.grep]
        matches = []
        for name, vas in unique_names.items():
            low = name.lower()
            if any(k in low for k in keys):
                matches.append((name, vas))
        matches.sort()
        print(f"\n[+] {len(matches)} names matching {args.grep!r}:")
        for name, vas in matches:
            print(f"    {name}")
            for va in vas[:3]:
                print(f"        TD_name @ {va}")

    # 常规摘要：类名带 Voice/Audio/Silk/Upload/Post/Send 的
    print(f"\n[+] Auto-summary（Voice/Audio/Silk/Amr/Media/Upload/Send/Post 关键类）:")
    keys = ("voice", "audio", "silk", "amr", "media", "upload", "sound",
            "postsend", "sendmsg", "sendmessage", "postmessage")
    hits = []
    for name in sorted(unique_names.keys()):
        low = name.lower()
        # 只挑 wework 命名空间下的
        if "wework" not in low: continue
        if any(k in low for k in keys):
            hits.append(name)
    for h in hits[:80]:
        print(f"    {h}")
    print(f"\n    (total {len(hits)} matches; full list in JSON)")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
