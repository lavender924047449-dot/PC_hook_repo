# 反汇编 0x17561d0（type5 里首个关键调用）
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
function cstr(p,n){ try{return p.readCString(n||60);}catch(e){return null;} }
function disasm(rva, maxBytes){
    const out={rva:'0x'+rva.toString(16), insns:[]};
    let cur=wx.base.add(rva), walked=0;
    for (let n=0;n<400 && walked<maxBytes;n++){
        let ins; try{ins=Instruction.parse(cur);}catch(e){break;}
        const line=('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr;
        out.insns.push(line);
        for (const op of ins.operands||[]){
            if (op.type==='imm'){
                const v=op.value>>>0;
                if (v>=W0 && v<W0+wx.size){
                    const s=cstr(ptr(v), 80);
                    if (s && /^[\x20-\x7e]{6,}$/.test(s)){
                        out.insns.push('   ; str: '+s.slice(0,80));
                    }
                }
            }
        }
        if (ins.mnemonic==='ret'){ out.ret='+0x'+walked.toString(16); break; }
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}
send({fn_17561d0: disasm(0x17561d0, 0x200)});
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
print(json.dumps(res, indent=2))
sc.unload(); s.detach()
