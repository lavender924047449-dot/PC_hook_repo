# 找写 CdnUploadParam vtable 的 ctor（mov [reg], CDN_VT）
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const VT = (W0 + 0xB795B58) >>> 0;
const pat = [(VT&255),((VT>>>8)&255),((VT>>>16)&255),((VT>>>24)&255)]
    .map(b=>b.toString(16).padStart(2,'0')).join(' ');

const text = Process.enumerateRanges({protection:'r-x',coalesce:true})
    .filter(r=>r.base.toUInt32()>=W0 && r.base.toUInt32()<W0+wx.size);
const sites=[];
for (const r of text){
    let ms; try{ ms=Memory.scanSync(r.base, r.size, pat);}catch(e){continue;}
    for (const m of ms){
        const va = m.address.toUInt32();
        const rva = va - W0;
        // 前 8 字节是否像 mov [reg], imm
        const pre = new Uint8Array(ptr(va-6).readByteArray(8));
        sites.push({site_rva:'0x'+rva.toString(16), pre:Array.from(pre).map(b=>b.toString(16).padStart(2,'0')).join(' ')});
    }
}

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function snap(p){ const a=[]; for(let k=0;k<11;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }

// 从每个 site 回溯找函数头（push ebp; mov ebp,esp 或 push esi; mov esi,ecx）
function findFnStart(rva){
    for (let back=0; back<0x80; back+=1){
        const p = wx.base.add(rva-back);
        const b = new Uint8Array(p.readByteArray(3));
        if (b[0]===0x55 && b[1]===0x8B && b[2]===0xEC) return rva-back;
        if (b[0]===0x56 && b[1]===0x8B && b[2]===0xCE) return rva-back; // push esi; mov esi, ecx
    }
    return null;
}

const fns={};
for (const s of sites){
    const rva = parseInt(s.site_rva,16);
    const fn = findFnStart(rva);
    if (!fn) continue;
    const key = '0x'+fn.toString(16);
    if (!fns[key]) fns[key]=[];
    fns[key].push(s.site_rva);
}

const tested=[];
const keys = Object.keys(fns).slice(0,16);
for (const k of keys){
    const rva = parseInt(k,16);
    const p = Memory.alloc(0x40);
    const rec = {fn:k, sites:fns[k]};
    try {
        new NativeFunction(wx.base.add(rva), 'void', ['pointer'], 'thiscall')(p);
        rec.thiscall=true; rec.vt='0x'+u32(p).toString(16);
        rec.match = u32(p)===(W0+0xB795B58);
        rec.snap=snap(p);
    } catch(e){ rec.thiscall_err=e.message; }
    if (!rec.match){
        try {
            new NativeFunction(wx.base.add(rva), 'void', ['pointer'], 'stdcall')(p);
            rec.stdcall=true; rec.vt='0x'+u32(p).toString(16);
            rec.match = u32(p)===(W0+0xB795B58);
            rec.snap=snap(p);
        } catch(e2){ rec.stdcall_err=e2.message; }
    }
    tested.push(rec);
}
send({sites: sites.length, fns: Object.keys(fns).length, tested: tested});
"""
pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res = {}
sc.on('message', lambda m,_: res.update(m.get('payload',{})))
sc.load(); import time; time.sleep(3)
print(json.dumps(res, indent=2))
sc.unload(); s.detach()
