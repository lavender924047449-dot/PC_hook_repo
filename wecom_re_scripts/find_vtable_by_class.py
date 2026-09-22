# find_vtable_by_class.py — M1c 补丁 · 由类名反查 vtable RVA
# =============================================================================
#
# 反查流程（MSVC 32-bit RTTI）：
#   1) 全内存扫 ".?AV<Name>@" 字符串 → TypeDescriptor.name 的 VA
#      TypeDescriptor 起点 = name_VA - 8
#   2) 全内存扫 dword == TD_VA 找到指向 TD 的位置（那是 COL.TypeDescriptor 字段）
#      COL 起点 = 上述位置 - 0xc
#   3) 全内存扫 dword == COL_VA 找到 vtable[-1] 位置 → vtable 起点 = 该位置 + 4
#
# 用法：
#   python runtime/wecom_re/find_vtable_by_class.py HandleMessageResourcesTask
#   python runtime/wecom_re/find_vtable_by_class.py PostSendMessageTask2 HandleMessageResourcesTask HandleForwardResourcesTask2
#
# 严格约束：只读扫，不 hook。
# =============================================================================

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")


FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base;
const WXSIZE = wx.size;
const WXBASE_U32 = WXBASE.toUInt32();
send({t:'info', msg:'wx base=' + WXBASE + ' size=0x' + WXSIZE.toString(16)});

function safeCstr(p, cap){ try { return p.readCString(cap || 512); } catch(e){ return null; } }
function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }

function nameToPattern(name){
    // ".?AV<name>@" as a byte pattern
    const s = '.?AV' + name + '@';
    let p = '';
    for (let i = 0; i < s.length; i++){
        const b = s.charCodeAt(i).toString(16).padStart(2, '0');
        p += (i ? ' ' : '') + b;
    }
    return p;
}

function u32ToPattern(v){
    const b0 = (v & 0xff).toString(16).padStart(2, '0');
    const b1 = ((v >>> 8) & 0xff).toString(16).padStart(2, '0');
    const b2 = ((v >>> 16) & 0xff).toString(16).padStart(2, '0');
    const b3 = ((v >>> 24) & 0xff).toString(16).padStart(2, '0');
    return b0 + ' ' + b1 + ' ' + b2 + ' ' + b3;
}

rpc.exports = {
    findVtables: function(names){
        const results = [];
        for (let n = 0; n < names.length; n++){
            const name = names[n];
            const rec = {name:name, td_name_hits:[], col_hits:[], vtables:[]};

            // Step 1: find TD.name VA
            let hits;
            try { hits = Memory.scanSync(WXBASE, WXSIZE, nameToPattern(name)); }
            catch(e){ rec.err = 'scan name failed: ' + e.message; results.push(rec); continue; }
            for (let i = 0; i < hits.length; i++){
                rec.td_name_hits.push(hits[i].address.toString());
            }
            if (hits.length === 0){
                rec.err = 'class name not found';
                results.push(rec); continue;
            }

            // 尝试每个 name hit → TD → COL → vtable
            for (let i = 0; i < hits.length; i++){
                const nameVA = hits[i].address;
                const tdVA = nameVA.sub(8);
                const tdVA_u32 = tdVA.toUInt32();

                // Step 2: find dword == td_va (COL.TypeDescriptor)
                let tdRefs;
                try { tdRefs = Memory.scanSync(WXBASE, WXSIZE, u32ToPattern(tdVA_u32)); }
                catch(e){ continue; }
                for (let j = 0; j < tdRefs.length; j++){
                    const tdRefVA = tdRefs[j].address;
                    // COL = tdRefVA - 0xc
                    const colVA = tdRefVA.sub(0xc);
                    const colVA_u32 = colVA.toUInt32();
                    // 简单校验：COL.signature == 0
                    let sig;
                    try { sig = u32(colVA); } catch(e){ continue; }
                    if (sig !== 0 && sig !== 1) continue;  // 0=32-bit COL, 1=64-bit
                    rec.col_hits.push(colVA.toString());

                    // Step 3: find dword == col_va (vtable[-1])
                    let colRefs;
                    try { colRefs = Memory.scanSync(WXBASE, WXSIZE, u32ToPattern(colVA_u32)); }
                    catch(e){ continue; }
                    for (let k = 0; k < colRefs.length; k++){
                        const vtRef = colRefs[k].address;
                        const vtableVA = vtRef.add(4);
                        const rva = vtableVA.toUInt32() - WXBASE_U32;
                        rec.vtables.push({
                            va: vtableVA.toString(),
                            rva: '0x' + rva.toString(16),
                            slot0: '0x' + u32(vtableVA).toString(16),
                            slot1: '0x' + u32(vtableVA.add(4)).toString(16),
                            slot2: '0x' + u32(vtableVA.add(8)).toString(16),
                        });
                    }
                }
            }
            results.push(rec);
        }
        return results;
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("names", nargs="+", help="class names to find vtables for (no .?AV prefix)")
    args = ap.parse_args(argv)

    pid = args.pid or _find_wxwork_pid()
    if pid is None: print("[!] no WXWork.exe"); return 1
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

    print(f"[*] finding vtables for {len(args.names)} class(es)...")
    t0 = time.monotonic()
    results = script.exports_sync.find_vtables(args.names)
    print(f"[+] done in {time.monotonic()-t0:.1f}s")
    print()
    print("=" * 90)
    for r in results:
        print(f"\n{r['name']}")
        if r.get("err") and not r.get("vtables"):
            print(f"    ✗ {r['err']}")
        print(f"    TD name hits: {len(r.get('td_name_hits') or [])}")
        print(f"    COL candidates: {len(r.get('col_hits') or [])}")
        vts = r.get("vtables") or []
        print(f"    vtable candidates: {len(vts)}")
        for v in vts[:5]:
            print(f"      → vtable RVA {v['rva']}   VA {v['va']}")
            print(f"           slot[0..2] = [{v['slot0']}, {v['slot1']}, {v['slot2']}]")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
