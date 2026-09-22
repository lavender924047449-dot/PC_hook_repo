# 找 CdnUploadParam InitFromDefault（区别于 FtnUploadParam @0xA08B00）
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const COPY = 0x3A94A7;
const CDN_VT = 0xB795B58;

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||64);}catch(e){return null;} }
function snap(p,n){ const a=[]; for(let k=0;k<n;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }

// 扫 .text: push imm32; ... call copy
const text = Process.enumerateRanges({protection:'r-x',coalesce:true})
    .filter(r=>r.base.toUInt32()>=W0 && r.base.toUInt32()<W0+wx.size)[0];
const buf = new Uint8Array(text.base.readByteArray(text.size));
const wrappers=[];
for (let i=0;i<buf.length-16;i++){
    if (buf[i]!==0x68) continue; // push imm
    const imm = buf[i+1]|(buf[i+2]<<8)|(buf[i+3]<<16)|(buf[i+4]<<24);
    // 找后面 12 字节内 call copy
    for (let j=i+5;j<i+20 && j+4<buf.length;j++){
        if (buf[j]===0xE8){
            const rel = buf[j+1]|(buf[j+2]<<8)|(buf[j+3]<<16)|(buf[j+4]<<24);
            const tgt = (text.base.toUInt32()+i+j+5+rel)>>>0;
            if (tgt === W0+COPY){
                const site = text.base.toUInt32()+i;
                wrappers.push({rva:'0x'+(site-W0).toString(16), push:'0x'+(imm>>>0).toString(16)});
                break;
            }
        }
    }
}

const tested=[];
for (const w of wrappers.slice(0,40)){
    const param = Memory.alloc(0x40);
    for (let i=0;i<0x40;i+=4) param.add(i).writeU32(0);
    try {
        const fn = new NativeFunction(ptr(W0 + parseInt(w.rva,16)), 'void', ['pointer'], 'stdcall');
        fn(param);
        const vt = u32(param);
        const type = cstr(param, 32) || cstr(ptr(vt), 32);
        tested.push({...w, vt:'0x'+vt.toString(16), vt_match: vt===(W0+CDN_VT),
            snap:snap(param,11), type_hint: type});
    } catch(e){
        tested.push({...w, err:e.message});
    }
}

// 也试 CdnUploadParam 裸 ctor：写 vtable + empty strings @0xA08C56 前半？找 mov [esi], CDN_VT 且非 dtor 尾
send({wrappers_found: wrappers.length, tested: tested.filter(t=>t.vt_match || (t.type_hint||'').indexOf('CdnUpload')>=0 || (t.type_hint||'').indexOf('Upload')>=0)});
"""
pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res = {}
sc.on('message', lambda m,_: res.update(m.get('payload',{})))
sc.load(); import time; time.sleep(2)
print(json.dumps(res, indent=2))
sc.unload(); s.detach()
