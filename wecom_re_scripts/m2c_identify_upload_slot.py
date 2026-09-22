# m2c_identify_upload_slot.py — 深拆 FileService[2/6/7] + 找 CdnUploadParam default_instance
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\m2c_identify_slot.json")

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m => m.name.toLowerCase()==='wxwork.exe')[0];
const WX=wx.base, W0=WX.toUInt32(), SZ=wx.size;
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||160);}catch(e){return null;} }

function disasm(va, maxBytes){
    const out={va:'0x'+(va>>>0).toString(16), rva:'0x'+((va-W0)>>>0).toString(16),
              insns:[], strings:[], calls:[], imms:[]};
    let cur=ptr(va), walked=0;
    for (let n=0;n<360 && walked<maxBytes;n++){
        let ins; try{ins=Instruction.parse(cur);}catch(e){break;}
        const line=('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr;
        out.insns.push(line);
        if (ins.mnemonic==='call') out.calls.push({off:'0x'+walked.toString(16), op:ins.opStr});
        if (ins.mnemonic==='ret'){ out.retn=ins.opStr||'0'; break; }
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            out.imms.push('0x'+v.toString(16));
            if (v>=W0 && v<W0+SZ){
                const s=cstr(ptr(v),180);
                if (s && /^[\x20-\x7e]{4,160}$/.test(s)) out.strings.push(s);
            }
        }
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}

rpc.exports = {
    run: function(){
        const rvas=[0x2499bb0, 0x2499a20, 0x249c360];
        const names=['slot2','slot6','slot7'];
        const fns={};
        for (let i=0;i<rvas.length;i++){
            fns[names[i]] = disasm(WX.add(rvas[i]).toUInt32(), 0x400);
        }

        // default_instance: 在 wx 模块 r-- 段扫 CdnUploadParam vtable 指针
        const vt = 0xb955b58;
        const pat=[(vt)&255,(vt>>>8)&255,(vt>>>16)&255,(vt>>>24)&255]
            .map(b=>b.toString(16).padStart(2,'0')).join(' ');
        const ranges=Process.enumerateRanges({protection:'r--', coalesce:true});
        const inst=[];
        for (let i=0;i<ranges.length && inst.length<12;i++){
            const r=ranges[i];
            if (r.base.toUInt32()+r.size < W0 || r.base.toUInt32()>=W0+SZ) continue;
            let ms; try{ ms=Memory.scanSync(r.base, r.size, pat);}catch(e){continue;}
            for (let j=0;j<ms.length && inst.length<12;j++){
                const a=ms[j].address;
                const dw=[];
                for (let k=0;k<11;k++) dw.push('0x'+u32(a.add(k*4)).toString(16));
                inst.push({va:a.toString(), rva:'0x'+(a.toUInt32()-W0).toString(16), dwords:dw});
            }
        }

        const watch = {
            param_dtor: '0xbc8c56',
            param_vt: '0xb955b58',
            task_vt: '0xb64ca88',
            task_ctor: '0x91390c2',
            empty_str: '0xf54d940'
        };
        const hits={};
        const ks=Object.keys(fns);
        for (let i=0;i<ks.length;i++){
            const im=fns[ks[i]].imms||[];
            hits[ks[i]]={};
            const wks=Object.keys(watch);
            for (let j=0;j<wks.length;j++){
                hits[ks[i]][wks[j]] = im.indexOf(watch[wks[j]])>=0;
            }
        }

        return {fns:fns, default_instances:inst, imm_hits:hits};
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
        if msg.get("type") == "send" and msg["payload"].get("t") == "ready":
            ready["v"] = True
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_msg)
    script.load()
    for _ in range(40):
        if ready["v"]:
            break
        time.sleep(0.1)
    rec = script.exports_sync.run()
    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    OUT.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    print("[imm hits]")
    print(json.dumps(rec.get("imm_hits"), indent=2))
    print(f"\n[default_instance candidates] {len(rec.get('default_instances') or [])}")
    for d in rec.get("default_instances") or []:
        print(f"  {d['rva']} {d['dwords'][:8]}")
    for name, d in (rec.get("fns") or {}).items():
        print(f"\n==== {name} {d.get('rva')} retn={d.get('retn')} str={d.get('strings')[:8]} ====")
        for ins in (d.get("insns") or [])[:55]:
            print(f"  {ins}")
    print(f"[+] → {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
