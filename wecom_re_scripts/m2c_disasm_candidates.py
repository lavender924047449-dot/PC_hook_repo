# m2c_disasm_candidates.py — 反汇编 CdnUploadParam 构造点 + FileServiceImpl 槽表
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\m2c_disasm_candidates.json")

CAND_FNS = [
    0x249CC7D, 0x249CEEB, 0x249D378, 0x249D399,
    0x249D9B3, 0x249DA13, 0x249DC12, 0x249DD22,
    0xE53641, 0xE5384F, 0xE53F77, 0xE53FAE,
    0x4F918FA,
]
IMPL0 = 0xB48FAB4

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m => m.name.toLowerCase()==='wxwork.exe')[0];
const WX=wx.base, W0=WX.toUInt32(), SZ=wx.size;
send({t:'info', msg:'wx='+WX});
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||160);}catch(e){return null;} }

function disasm(rva, maxBytes){
    const fn=WX.add(rva).toUInt32();
    const out={rva:'0x'+rva.toString(16), va:'0x'+fn.toString(16), insns:[], strings:[], calls:[]};
    let cur=ptr(fn), walked=0;
    for (let n=0;n<280 && walked<maxBytes;n++){
        let ins; try{ ins=Instruction.parse(cur);}catch(e){break;}
        out.insns.push(('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr);
        if (ins.mnemonic==='call') out.calls.push({off:'0x'+walked.toString(16), op:ins.opStr});
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            if (v>=W0 && v<W0+SZ){
                const s=cstr(ptr(v),180);
                if (s && /^[\x20-\x7e]{4,120}$/.test(s)) out.strings.push(s);
            }
        }
        if (ins.mnemonic==='ret') break;
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}

rpc.exports = {
    run: function(cfgJson){
        const cfg=JSON.parse(cfgJson);
        const fns=[];
        for (let i=0;i<cfg.fns.length;i++){
            send({t:'info', msg:'disasm '+cfg.fns[i].toString(16)});
            fns.push(disasm(cfg.fns[i], 0x320));
        }
        const implSlots=[];
        const vt=WX.add(cfg.impl0);
        for (let i=0;i<96;i++){
            const fn=u32(vt.add(i*4));
            const rva = (fn>W0 && fn<W0+SZ) ? (fn-W0) : 0;
            implSlots.push({i:i, fn:'0x'+fn.toString(16), rva:rva?('0x'+rva.toString(16)):null});
        }
        return {fns:fns, impl_slots:implSlots};
    }
};
send({t:'ready'});
"""


def main() -> int:
    r = subprocess.run(
        ["powershell", "-Command",
         "Get-Process WXWork -ErrorAction SilentlyContinue | "
         "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True, encoding="utf-8",
    )
    pid = int(r.stdout.strip()) if r.stdout.strip() else None
    if not pid:
        print("[!] no WXWork")
        return 1
    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_msg(msg, _d):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "info":
                print(f"    [js] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_msg)
    script.load()
    for _ in range(40):
        if ready["v"]:
            break
        time.sleep(0.1)

    rec = script.exports_sync.run(json.dumps({"fns": CAND_FNS, "impl0": IMPL0}))
    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    OUT.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n[candidate functions]")
    for d in rec.get("fns") or []:
        print(f"\n==== {d['rva']}  str={d.get('strings')[:8]} ====")
        for ins in (d.get("insns") or [])[:40]:
            print(f"  {ins}")

    print("\n[FileServiceImpl slots whose rva in 0x2490000-0x24a0000 or 0xe53000]")
    for s in rec.get("impl_slots") or []:
        r = s.get("rva")
        if not r:
            continue
        v = int(r, 16)
        if 0x2490000 <= v <= 0x24B0000 or 0xE50000 <= v <= 0xE60000:
            print(f"  [{s['i']}] {r}")
    print(f"[+] → {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
