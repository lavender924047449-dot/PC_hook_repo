# 扫 Ftn/Cdn default_instance 邻近 rdata
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const CDN_VT = W0 + 0xB795B58;
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||48);}catch(e){return null;} }

const base = ptr(0xb955800);
const objs=[];
for (let off=0; off<0x400; off+=4){
    const a = base.add(off);
    const vt = u32(a);
    if (vt !== CDN_VT) continue;
    const dw=[]; for(let k=0;k<11;k++) dw.push('0x'+u32(a.add(k*4)).toString(16));
    objs.push({va:a.toString(), rva:'0x'+(a.toUInt32()-W0).toString(16), dwords:dw});
}

const copyFn = new NativeFunction(wx.base.add(0x3A94A7), 'void', ['pointer','pointer'], 'thiscall');
const tested=[];
for (const o of objs){
    const p = Memory.alloc(0x40);
    try {
        copyFn(p, ptr(parseInt(o.va,16)));
        tested.push({...o, copy_ok:true, snap: (()=>{const s=[];for(let k=0;k<11;k++)s.push('0x'+u32(p.add(k*4)).toString(16));return s;})()});
    } catch(e){ tested.push({...o, copy_err:e.message}); }
}
send({cdn_vt_hits: objs.length, tested: tested});
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
