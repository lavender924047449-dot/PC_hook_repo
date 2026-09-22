# m2c_disasm_fileservice.py — 拆 FileService 实现 vtable + 0x249e181 附近 + default_instance
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\m2c_fileservice_fn.json")

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m => m.name.toLowerCase()==='wxwork.exe')[0];
const WX=wx.base, W0=WX.toUInt32(), SZ=wx.size;
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||160);}catch(e){return null;} }

function disasm(va, maxBytes){
    const out={va:'0x'+(va>>>0).toString(16), rva:'0x'+((va-W0)>>>0).toString(16),
              insns:[], strings:[], retn:null};
    let cur=ptr(va), walked=0;
    for (let n=0;n<260 && walked<maxBytes;n++){
        let ins; try{ins=Instruction.parse(cur);}catch(e){break;}
        out.insns.push(('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr);
        if (ins.mnemonic==='ret'){
            out.retn = ins.opStr || '0';
            break;
        }
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            if (v>=W0 && v<W0+SZ){
                const s=cstr(ptr(v),160);
                if (s && /^[\x20-\x7e]{4,140}$/.test(s)) out.strings.push(s);
            }
        }
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}

rpc.exports = {
    run: function(){
        const vtRva=0xab69924;
        const vt=WX.add(vtRva);
        const slots=[];
        for (let i=0;i<24;i++){
            const fn=u32(vt.add(i*4));
            if (!fn || fn<W0 || fn>=W0+SZ){
                slots.push({i:i, fn:'0x'+fn.toString(16)});
                continue;
            }
            const d=disasm(fn, 0x220);
            slots.push({i:i, fn:'0x'+fn.toString(16), rva:d.rva, retn:d.retn,
                        strings:d.strings.slice(0,8), insns:d.insns.slice(0,22)});
        }

        // 0x249e181 附近反汇编（往前找 push ebp）
        const site=WX.add(0x249e181);
        let start=site;
        for (let b=0;b<=0x800;b++){
            const p=site.sub(b);
            try{
                if (p.readU8()===0x55 && p.add(1).readU8()===0x8b){ start=p; break; }
                if (p.readU8()===0x6a && p.add(1).readU8()===0xff && p.add(2).readU8()===0x68){
                    start=p; break;
                }
            }catch(e){break;}
        }
        const around=disasm(start.toUInt32(), 0x360);
        around.site_off = start.toUInt32()===site.toUInt32() ? 0 : (site.toUInt32()-start.toUInt32());

        // 读疑似 default_instance 0xb9559f0
        const di=ptr(0xb9559f0);
        const di_dwords=[];
        for (let i=0;i<12;i++) di_dwords.push('0x'+u32(di.add(i*4)).toString(16));

        // FileService / WinMember 对象头
        const objs={};
        const addrs={'WinMember':'0x2b5983c0','FileService_abs_d':'0x2b75f000','Impl0':'0x24b94bc4'};
        const ks=Object.keys(addrs);
        for (let i=0;i<ks.length;i++){
            const a=ptr(addrs[ks[i]]);
            const dw=[];
            for (let k=0;k<20;k++) dw.push('0x'+u32(a.add(k*4)).toString(16));
            objs[ks[i]]=dw;
        }

        return {slots:slots, around_249e181:around, default_instance:di_dwords, objs:objs};
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

    print("[FileService 0xab69924 slots]")
    for s in rec.get("slots") or []:
        print(f"  [{s.get('i')}] {s.get('rva')} retn={s.get('retn')} str={s.get('strings')}")
        for ins in (s.get("insns") or [])[:8]:
            print(f"      {ins}")

    print("\n[around 0x249e181]")
    a = rec.get("around_249e181") or {}
    print(f"  start {a.get('rva')} site_off={a.get('site_off')} str={a.get('strings')}")
    for ins in (a.get("insns") or [])[:50]:
        print(f"  {ins}")

    print("\n[default_instance 0xb9559f0]", rec.get("default_instance"))
    print("[objs]")
    for k, v in (rec.get("objs") or {}).items():
        print(f"  {k}: {v[:8]}")
    print(f"[+] → {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
