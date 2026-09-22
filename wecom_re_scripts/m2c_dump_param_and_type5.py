# m2c_dump_param_and_type5.py — 扫堆 CdnUploadParam + 反汇编 type=5 处理函数
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\m2c_param_layout.json")

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m => m.name.toLowerCase()==='wxwork.exe')[0];
const WX=wx.base, W0=WX.toUInt32();
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||200);}catch(e){return null;} }

function tryStdString(base){
    try{
        const size=u32(base.add(0x10)), cap=u32(base.add(0x14)), p=u32(base);
        if (size>0x10000 || cap<size || cap>0x400000) return null;
        let dp=base;
        if (size>15){ if (p<0x10000) return null; dp=ptr(p); }
        const b=new Uint8Array(dp.readByteArray(size));
        let s='';
        for (let i=0;i<size;i++) s += (b[i]>=0x20&&b[i]<0x7f)?String.fromCharCode(b[i]):'?';
        return {size:size, cap:cap, str:s};
    }catch(e){return null;}
}

function disasm(va, maxBytes){
    const out={rva:'0x'+(va-W0).toString(16), insns:[], strings:[]};
    let cur=ptr(va), walked=0;
    for (let n=0;n<220 && walked<maxBytes;n++){
        let ins; try{ins=Instruction.parse(cur);}catch(e){break;}
        out.insns.push(('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr);
        if (ins.mnemonic==='ret') break;
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            if (v>0x10000){
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
        const vt=0xb955b58;
        const pat=[vt&255,(vt>>>8)&255,(vt>>>16)&255,(vt>>>24)&255]
            .map(b=>b.toString(16).padStart(2,'0')).join(' ');
        const ranges=Process.enumerateRanges({protection:'rw-', coalesce:false});
        const objs=[];
        for (let i=0;i<ranges.length && objs.length<16;i++){
            const r=ranges[i];
            if (r.file) continue;
            if (r.size<0x1000 || r.size>0x4000000) continue;
            let ms; try{ms=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
            for (let j=0;j<ms.length && objs.length<16;j++){
                const a=ms[j].address;
                const dw=[];
                for (let k=0;k<11;k++) dw.push('0x'+u32(a.add(k*4)).toString(16));
                const fields={};
                for (const off of [0x10,0x14,0x18,0x4]){
                    const p=u32(a.add(off));
                    let s=null;
                    if (p>0x10000){
                        s=cstr(ptr(p),160);
                        const std=tryStdString(ptr(p));
                        const stdAt=tryStdString(a.add(off));
                        fields['+0x'+off.toString(16)]={u32:'0x'+p.toString(16), cstr:s, std_as_ptr:std, std_inline:stdAt};
                    } else {
                        fields['+0x'+off.toString(16)]={u32:'0x'+p.toString(16)};
                    }
                }
                objs.push({va:a.toString(), dwords:dw, file_type:u32(a.add(0x1c)), fields:fields});
            }
        }

        const type5=disasm(0x265cf20, 0x280);
        const typeOther=disasm(0x2659c2d, 0x200);
        const type123=disasm(0x2659d23, 0x80);
        const strHelper=disasm(0x6bc07d, 0x80);

        const win=ptr('0x2b5983c0');
        const win48=u32(win.add(0x48));
        const fs=ptr('0x2b75f000');
        const fs10=u32(fs.add(0x10));

        return {
            params:objs,
            type5:type5,
            type_other:typeOther,
            type123:type123,
            str_helper:strHelper,
            winmember_plus48:'0x'+win48.toString(16),
            fileservice_plus10:'0x'+fs10.toString(16)
        };
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

    print(f"[WinMember+0x48]={rec.get('winmember_plus48')}  FileService+0x10={rec.get('fileservice_plus10')}")
    print(f"[heap CdnUploadParam] {len(rec.get('params') or [])}")
    for p in rec.get("params") or []:
        print(f"  {p['va']} type={p['file_type']} dw={p['dwords']}")
        print(f"    fields={p['fields']}")
    print("\n[type5 0x265cf20] str=", rec.get("type5", {}).get("strings"))
    for ins in (rec.get("type5") or {}).get("insns", [])[:40]:
        print(" ", ins)
    print("\n[type other 0x2659c2d] str=", rec.get("type_other", {}).get("strings"))
    for ins in (rec.get("type_other") or {}).get("insns", [])[:30]:
        print(" ", ins)
    print("\n[str helper 0x6bc07d]")
    for ins in (rec.get("str_helper") or {}).get("insns", [])[:20]:
        print(" ", ins)
    print(f"[+] → {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
