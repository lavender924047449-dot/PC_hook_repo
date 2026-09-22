# 探测 CdnUploadParam 手工构造 + empty callback
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
try {
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const CDN_VT = W0 + 0xB795B58;
const EMPTY = ptr(0xf54d940);

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function snap(p,n){ const a=[]; for(let k=0;k<n;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }

const strFrom = new NativeFunction(wx.base.add(0x6BC07D), 'void', ['pointer','pointer'], 'thiscall');
const field4 = new NativeFunction(wx.base.add(0x6BC0C3), 'void', ['pointer'], 'thiscall');

function initCdnParam(p){
    p.writeU32(CDN_VT);
    strFrom(p.add(0x10), EMPTY);
    strFrom(p.add(0x14), EMPTY);
    strFrom(p.add(0x18), EMPTY);
    field4(p.add(0x04));
    for (let off=0x1c; off<0x2c; off+=4) p.add(off).writeU32(0);
}

const param = Memory.alloc(0x40);
initCdnParam(param);
const out = {after_ctor: snap(param, 11), vt_ok: u32(param)===CDN_VT};

// 写 path + file_type
function writeSSO(base, s){
    const n=s.length;
    if (n>15) throw new Error('long');
    const buf=new Uint8Array(16);
    for(let i=0;i<n;i++) buf[i]=s.charCodeAt(i);
    base.writeByteArray(buf.buffer);
    base.add(0x10).writeU32(n);
    base.add(0x14).writeU32(15);
}
const path = Memory.alloc(512);
const ps = 'C:\\Users\\LENOVO\\Documents\\WXWork\\1688855042791155\\Cache\\Voice\\2026-09\\2026_09_13_19_10_59_135.silk';
const arr=new Uint8Array(ps.length);
for(let i=0;i<ps.length;i++) arr[i]=ps.charCodeAt(i);
const heap=Memory.alloc(ps.length+1);
heap.writeByteArray(arr.buffer);
path.writeU32(heap.toUInt32());
path.add(0x10).writeU32(ps.length);
path.add(0x14).writeU32(ps.length);
// copy path std::string to param+0x10 via assign helper
try {
    strFrom(param.add(0x10), path); // might wrong
} catch(e){ out.path_assign_err=e.message; }

param.add(0x1c).writeU32(5);
out.after_patch = snap(param, 11);

// 试 CdnUploadFile：零 callback vs 跳过
const fs = ptr('0x2b75f000');
const cb0 = Memory.alloc(0x40);
const cb1 = Memory.alloc(0x40);
for(let i=0;i<0x40;i+=4){ cb0.add(i).writeU32(0); cb1.add(i).writeU32(0); }

const upload = new NativeFunction(wx.base.add(0x2499BB0), 'void',
    ['pointer','pointer','pointer','pointer'], 'thiscall');
try {
    upload(fs, param, cb0, cb1);
    out.upload_ok = true;
} catch(e){ out.upload_err = e.message; }

send(out);
}catch(e){ send({fatal:e.message, stack:e.stack}); }
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
