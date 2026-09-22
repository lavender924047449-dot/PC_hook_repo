# 读 empty string @0xf54d940 + 试 string assign
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const EMPTY = ptr(0xf54d940);
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function snap(p,n){ const a=[]; for(let k=0;k<n;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }
const out = {empty: snap(EMPTY, 6), empty_size: u32(EMPTY.add(0x10)), empty_cap: u32(EMPTY.add(0x14))};

const dest = Memory.alloc(0x20);
for(let i=0;i<0x20;i+=4) dest.add(i).writeU32(0);
const strFrom = new NativeFunction(wx.base.add(0x6BC07D), 'void', ['pointer','pointer'], 'thiscall');
try { strFrom(dest, EMPTY); out.assign_ok=true; out.dest=snap(dest,6); } catch(e){ out.assign_err=e.message; }

// 直接调 CdnUploadParam ctor 前半：仅写 vtable + 不调 string?
const p = Memory.alloc(0x40);
p.writeU32(wx.base.toUInt32() + 0xB795B58);
out.manual_vt = snap(p,11);
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
