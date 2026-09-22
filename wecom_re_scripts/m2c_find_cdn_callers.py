# 在整个 .text 里找 call CdnUploadFile (slot2 @ 0x2499BB0) 或通过 vtable 的调用者
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const TARGET = W0 + 0x2499BB0;   // CdnUploadFile
const FS_VT = W0 + 0xAB69924;

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||80);}catch(e){return null;} }

// direct E8 rel32 calls
const text = Process.enumerateRanges({protection:'r-x',coalesce:true})
    .filter(r=>r.base.toUInt32()>=W0 && r.base.toUInt32()<W0+wx.size)[0];
const buf = new Uint8Array(text.base.readByteArray(text.size));
const direct=[];
for (let i=0;i<buf.length-5;i++){
    if (buf[i]!==0xE8) continue;
    const rel = (buf[i+1]|(buf[i+2]<<8)|(buf[i+3]<<16)|(buf[i+4]<<24))|0;
    const tgt = (text.base.toUInt32()+i+5+rel)>>>0;
    if (tgt === TARGET){
        direct.push({site_rva:'0x'+(text.base.toUInt32()+i-W0).toString(16)});
        if (direct.length >= 40) break;
    }
}

// slot 2 xref: mov reg, [vt+8] → call reg  find `mov eax, [imm+8]` where imm = FS_VT
// simpler: find any indirect via [imm+8] where imm = FS_VT (WinMember vtable+0x8 = slot2)
const indirect=[];
const patVt = [(FS_VT+8)&255,((FS_VT+8)>>>8)&255,((FS_VT+8)>>>16)&255,((FS_VT+8)>>>24)&255]
    .map(b=>b.toString(16).padStart(2,'0')).join(' ');

// FileService heap object at 0x2b75f000; [obj]=vt; slot2 accessed via [obj]+8
// Callers usually: mov ecx, obj; mov eax, [ecx]; call [eax+8]

// Better: find call sites which push 3 args then call some function tail-calling CdnUploadFile
// simplistic: search for `.silk` string refs and inline paths
const silkRefs=[];
const silk = Memory.scanSync(text.base, text.size, '2e 73 69 6c 6b'); // ".silk"
for (const m of silk.slice(0,10)){
    silkRefs.push('0x'+(m.address.toUInt32()-W0).toString(16));
}

send({direct_callers: direct, silk_refs: silkRefs});
"""
pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida, time
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res={}
sc.on('message', lambda m,_: res.update(m.get('payload',{})))
sc.load(); time.sleep(3)
print(json.dumps(res, indent=2))
sc.unload(); s.detach()
