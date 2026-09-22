# 一次性探测：CdnUploadParam default + init/copy 调用约定
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function snap(p,n){ const a=[]; for(let k=0;k<n;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }

const def = ptr(0xb9559f0);
const out = {
    def_va: def.toString(),
    def_rva: '0x'+(def.toUInt32()-W0).toString(16),
    def_dwords: snap(def, 12),
    def_vtable_match: u32(def) === W0 + 0xB795B58,
};

const param = Memory.alloc(0x40);
Memory.protect(param, 0x40, 'rw-');
for (let i=0;i<0x40;i+=4) param.add(i).writeU32(0);

// wrapper: void __stdcall InitFromDefault(CdnUploadParam* out)
try {
    const initFn = new NativeFunction(wx.base.add(0xA08B00), 'void', ['pointer'], 'stdcall');
    initFn(param);
    out.init_wrapper_ok = true;
    out.param_after_wrapper = snap(param, 12);
} catch(e){ out.init_wrapper_err = e.message; }

// copy: thiscall dest=ecx, src on stack
if (!out.init_wrapper_ok){
    try {
        const copyFn = new NativeFunction(wx.base.add(0x3A94A7), 'void', ['pointer','pointer'], 'thiscall');
        copyFn(param, def);
        out.copy_ok = true;
        out.param_after_copy = snap(param, 12);
    } catch(e){ out.copy_err = e.message; }
}

// scan rdata for vtable in module
const pat = [(W0+0xB795B58)&255,((W0+0xB795B58)>>>8)&255,((W0+0xB795B58)>>>16)&255,((W0+0xB795B58)>>>24)&255]
    .map(b=>b.toString(16).padStart(2,'0')).join(' ');
const hits=[];
for (const r of Process.enumerateRanges({protection:'r--',coalesce:true})){
    if (r.base.toUInt32()+r.size < W0 || r.base.toUInt32() >= W0+wx.size) continue;
    let ms; try{ ms=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
    for (const m of ms) hits.push({va:m.address.toString(),rva:'0x'+(m.address.toUInt32()-W0).toString(16),d:snap(m.address,12)});
}
out.rdata_hits = hits.slice(0,8);
send(out);
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
