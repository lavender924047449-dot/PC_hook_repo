# 反汇编 file_type != 1/2/3/5 的通用 handler
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||120);}catch(e){return null;} }
function disasm(rva, maxBytes){
    const out={rva:'0x'+rva.toString(16), insns:[]};
    let cur=wx.base.add(rva), walked=0;
    for (let n=0;n<800 && walked<maxBytes;n++){
        let ins; try{ins=Instruction.parse(cur);}catch(e){break;}
        out.insns.push(('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr);
        for (const op of ins.operands||[]){
            if (op.type==='imm'){
                const v=op.value>>>0;
                if (v>=W0 && v<W0+wx.size){
                    const s=cstr(ptr(v));
                    if (s && /^[\x20-\x7e]{6,}$/.test(s))
                        out.insns.push('    ; str: '+s.slice(0,100));
                }
            }
        }
        if (ins.mnemonic==='ret'){ out.ret='+0x'+walked.toString(16); break; }
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}
send({type_other: disasm(0x2499C2D, 0x400)});
"""
pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida, time
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res={}
sc.on('message', lambda m,_: res.update(m.get('payload',{})))
sc.load(); time.sleep(0.5)
print(json.dumps(res, ensure_ascii=False, indent=2))
sc.unload(); s.detach()
