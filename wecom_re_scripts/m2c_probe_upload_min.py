# 最小路径：Ftn init → Cdn vtable → path@+0x10 → file_type=5 → upload
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const CDN_VT = W0 + 0xB795B58;

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function snap(p,n){ const a=[]; for(let k=0;k<n;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }
function writeStdString(base, s){
    const n=s.length, arr=new Uint8Array(n);
    for(let i=0;i<n;i++) arr[i]=s.charCodeAt(i)&0xff;
    if (n<=15){
        const buf=new Uint8Array(16);
        for(let i=0;i<n;i++) buf[i]=arr[i];
        base.writeByteArray(buf.buffer);
        base.add(0x10).writeU32(n);
        base.add(0x14).writeU32(15);
        return;
    }
    const heap=Memory.alloc(n+1); heap.writeByteArray(arr.buffer);
    base.writeU32(heap.toUInt32()); base.add(0x10).writeU32(n); base.add(0x14).writeU32(n);
}

const ps = 'C:\\Users\\LENOVO\\Documents\\WXWork\\1688855042791155\\Cache\\Voice\\2026-09\\2026_09_13_19_10_59_135.silk';
const param = Memory.alloc(0x40);
new NativeFunction(wx.base.add(0xA08B00), 'void', ['pointer'], 'stdcall')(param);
param.writeU32(CDN_VT);
writeStdString(param.add(0x10), ps);
param.add(0x1c).writeU32(5);

const out = {param: snap(param,11)};

const fs = ptr('0x2b75f000');
const upload = new NativeFunction(wx.base.add(0x2499BB0), 'void',
    ['pointer','pointer','pointer','pointer'], 'thiscall');

function countTasks(){
    const pat=[(W0+0xB48CA88)&255,((W0+0xB48CA88)>>>8)&255,((W0+0xB48CA88)>>>16)&255,((W0+0xB48CA88)>>>24)&255]
        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
    let n=0; for(const r of Process.enumerateRanges({protection:'rw-',coalesce:false})){
        if(r.file) continue; try{n+=Memory.scanSync(r.base,r.size,pat).length;}catch(e){}
    } return n;
}
out.before = countTasks();

const tries = [
    {name:'null_cb', cb0:ptr(0), cb1:ptr(0)},
    {name:'zero_alloc', cb0:Memory.alloc(0x40), cb1:Memory.alloc(0x40)},
];
for (const t of tries){
    if (t.name==='zero_alloc'){
        for(let i=0;i<0x40;i+=4){ t.cb0.add(i).writeU32(0); t.cb1.add(i).writeU32(0); }
    }
    try {
        upload(fs, param, t.cb0, t.cb1);
        t.ok = true;
    } catch(e){ t.err = e.message; }
    t.tasks = countTasks();
    out[t.name] = t;
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
sc.on('message', lambda m,_: res.update(m.get('payload',{})))
sc.load(); import time; time.sleep(1)
print(json.dumps(res, indent=2))
sc.unload(); s.detach()
