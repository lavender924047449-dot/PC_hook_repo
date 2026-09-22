# 单独测 0x17561d0(path) — type5 第一步
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const ps = 'C:\\Users\\LENOVO\\Documents\\WXWork\\1688855042791155\\Cache\\Voice\\2026-09\\2026_09_13_19_10_59_135.silk';
const pathMem = Memory.allocUtf8String(ps);
const statFn = new NativeFunction(ptr(0x17561d0), 'void', ['pointer','pointer'], 'thiscall');
// 猜: ecx=output, [stack]=path string ptr or path char*
const out = Memory.alloc(0x80);
const out2 = Memory.alloc(0x80);
const tries=[];
for (const t of ['charptr','stringobj']){
    const rec={type:t};
    try {
        if (t==='charptr'){
            statFn(out, pathMem);
        } else {
            const sob = Memory.alloc(0x20);
            sob.writeU32(pathMem.toUInt32());
            sob.add(0x10).writeU32(ps.length);
            sob.add(0x14).writeU32(ps.length);
            statFn(out2, sob);
        }
        rec.ok=true;
    } catch(e){ rec.err=e.message; }
    tries.push(rec);
}
send({tries, pathMem:pathMem.toString()});
"""
pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res = {}
sc.on('message', lambda m,_: res.update(m.get('payload',{})))
sc.load(); import time; time.sleep(0.5)
print(json.dumps(res, indent=2))
sc.unload(); s.detach()
