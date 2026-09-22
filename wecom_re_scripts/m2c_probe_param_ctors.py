# 试 CdnUploadParam 各 ctor / vtable[0] 候选
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const CDN_VT = W0 + 0xB795B58;
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||40);}catch(e){return null;} }
function snap(p,n){ const a=[]; for(let k=0;k<n;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }

const ctors = [0xA08B00, 0xA08B80, 0xA08BC8, 0xA08C56, 0xA08CA0, 0xA08D10];
const out = [];
for (const rva of ctors){
    const p = Memory.alloc(0x40);
    for (let i=0;i<0x40;i+=4) p.add(i).writeU32(0);
    const rec = {rva:'0x'+rva.toString(16)};
    try {
        const fn = new NativeFunction(wx.base.add(rva), 'void', ['pointer'], 'stdcall');
        fn(p);
        rec.stdcall_ok = true;
    } catch(e1){
        rec.stdcall_err = e1.message;
        try {
            const fn2 = new NativeFunction(wx.base.add(rva), 'void', ['pointer'], 'thiscall');
            fn2(p);
            rec.thiscall_ok = true;
        } catch(e2){ rec.thiscall_err = e2.message; }
    }
    rec.vt = '0x'+u32(p).toString(16);
    rec.vt_match = u32(p)===CDN_VT;
    rec.snap = snap(p,11);
    // 读 SSO @+0x0 附近类型名
    const s0 = cstr(p, 24);
    if (s0) rec.cstr0 = s0;
    out.push(rec);
}
send(out);
"""
pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res = {}
sc.on('message', lambda m,_: res.update({'items': m.get('payload',[])}) if m.get('type')=='send' else None)
sc.load(); import time; time.sleep(1)
print(json.dumps(res.get('items', res), indent=2))
sc.unload(); s.detach()
