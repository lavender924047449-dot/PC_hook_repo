# 直调 type5 handler + path ptr/len
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
try {
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const CDN_VT = W0 + 0xB795B58;
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function snap(p,n){ const a=[]; for(let k=0;k<n;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }

const ps = 'C:\\Users\\LENOVO\\Documents\\WXWork\\1688855042791155\\Cache\\Voice\\2026-09\\2026_09_13_19_10_59_135.silk';
const pathMem = Memory.allocUtf8String(ps);

function makeParam(mode){
    const p = Memory.alloc(0x40);
    for(let i=0;i<0x40;i+=4) p.add(i).writeU32(0);
    new NativeFunction(wx.base.add(0xA08B00), 'void', ['pointer'], 'stdcall')(p);
    p.writeU32(CDN_VT);
    if (mode==='ptr'){
        p.add(0x10).writeU32(pathMem.toUInt32());
        p.add(0x14).writeU32(0);
    } else if (mode==='ptr_len'){
        p.add(0x10).writeU32(pathMem.toUInt32());
        p.add(0x14).writeU32(ps.length);
    } else if (mode==='str'){
        // SSO at +0x10 impossible for long path; skip
    }
    p.add(0x1c).writeU32(5);
    return p;
}

const win = ptr('0x2b5983c0');
const cb = Memory.alloc(0x40);
const type5 = new NativeFunction(wx.base.add(0x249CF20), 'void',
    ['pointer','pointer','pointer','pointer'], 'thiscall');

const out = {before:0};
const pat=[(W0+0xB48CA88)&255,((W0+0xB48CA88)>>>8)&255,((W0+0xB48CA88)>>>16)&255,((W0+0xB48CA88)>>>24)&255]
    .map(b=>b.toString(16).padStart(2,'0')).join(' ');
function count(){ let n=0; for(const r of Process.enumerateRanges({protection:'rw-',coalesce:false})){
    if(r.file) continue; try{n+=Memory.scanSync(r.base,r.size,pat).length;}catch(e){}} return n; }
out.before = count();

for (const mode of ['ptr','ptr_len']){
    const param = makeParam(mode);
    const rec = {mode:mode, param:snap(param,11)};
    try { type5(win, param, cb, cb); rec.ok=true; } catch(e){ rec.err=e.message; }
    rec.tasks = count();
    out[mode]=rec;
}
send(out);
} catch(e){ send({fatal:e.message}); }
"""
pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res = {}
sc.on('message', lambda m,_: res.update(m.get('payload',{})))
sc.load(); import time; time.sleep(1)
print(json.dumps(res, indent=2))
sc.unload(); s.detach()
