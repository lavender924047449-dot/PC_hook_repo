# identify_vtable.py — M1c · 读 vtable RTTI complete-object-locator 拿类名
# =============================================================================
#
# MSVC 32-bit COM RTTI 布局：
#   vtable-4  → RTTIcompleteObjectLocator*
#   COL layout:
#     +0x00  signature (=0)
#     +0x04  offset
#     +0x08  cdOffset
#     +0x0c  TypeDescriptor*   ← 类名在这里
#     +0x10  ClassHierarchyDescriptor*
#   TypeDescriptor:
#     +0x00  pVFTable (type_info vtable)
#     +0x04  spare
#     +0x08  name string   ".?AVPostSendMessageTask2@logic@wework@@\0" (mangled)
#
# 用法：
#   python runtime/wecom_re/identify_vtable.py 0xabce098 0xabce07c 0xabc7e9c 0xabc7cf4
#
# 严格约束：只读 attach，不 hook。
# =============================================================================

from __future__ import annotations

import argparse
import subprocess
import sys
import time
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
const WXBASE = wx.base.toUInt32();
send({t:'info', msg:'wx base=0x'+WXBASE.toString(16)});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function safeCstr(p, cap){ try { return p.readCString(cap || 256); } catch(e){ return null; } }

rpc.exports = {
    identify: function(rvaHexList){
        const out = [];
        for (let i = 0; i < rvaHexList.length; i++){
            const rva = parseInt(rvaHexList[i], 16);
            const vtableVA = WXBASE + rva;
            const r = {rva:'0x'+rva.toString(16), vtable:'0x'+vtableVA.toString(16)};
            try {
                // vtable-4 = complete object locator (COL)
                const colVA = u32(ptr(vtableVA - 4));
                r.col = '0x' + colVA.toString(16);
                if (!colVA){ r.err = 'null COL'; out.push(r); continue; }
                // COL.signature at +0
                r.col_sig = u32(ptr(colVA));
                // COL.TypeDescriptor at +0xc
                const tdVA = u32(ptr(colVA + 0xc));
                r.td = '0x' + tdVA.toString(16);
                if (!tdVA){ r.err = 'null TD'; out.push(r); continue; }
                // TypeDescriptor.name at +8 (raw C string, mangled with .?AV prefix)
                const name = safeCstr(ptr(tdVA + 8), 256);
                r.mangled = name;
                // First 3~5 vtable slots (first virtual method entries)
                const slots = [];
                for (let s = 0; s < 8; s++){
                    slots.push('0x' + u32(ptr(vtableVA + s * 4)).toString(16));
                }
                r.vtable_slots = slots;
            } catch(e){
                r.err = 'exception: ' + e.message;
            }
            out.push(r);
        }
        return out;
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


def demangle(mangled: str) -> str:
    """
    简易 MSVC C++ demangler：
    `.?AVPostSendMessageTask2@logic@wework@@` → `wework::logic::PostSendMessageTask2`
    """
    if not mangled or not mangled.startswith(".?A"):
        return mangled or "(none)"
    body = mangled[4:] if mangled.startswith(".?AV") or mangled.startswith(".?AU") else mangled[3:]
    if body.endswith("@@"): body = body[:-2]
    parts = [p for p in body.split("@") if p]
    if not parts: return mangled
    return "::".join(reversed(parts))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="identify vtable RTTI class name")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("rvas", nargs="+", help="vtable RVA (hex) list, e.g. 0xabce098")
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

    print(f"[*] querying {len(args.rvas)} vtable(s)...")
    results = script.exports_sync.identify(args.rvas)

    print()
    print("=" * 90)
    for r in results:
        cls = demangle(r.get("mangled", "") or "")
        print(f"\nRVA={r['rva']}  VA={r['vtable']}")
        if r.get("err"):
            print(f"    ✗ {r['err']}")
            continue
        print(f"    COL   = {r.get('col')}  sig={r.get('col_sig')}")
        print(f"    TD    = {r.get('td')}")
        print(f"    mangled = {r.get('mangled')!r}")
        print(f"    class   = {cls}")
        slots = r.get("vtable_slots") or []
        if slots:
            print(f"    vtable[0..7] = {slots}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
