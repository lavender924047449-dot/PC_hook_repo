# Frida 扫 InitFromDefault wrappers (push default; call copy 0x3A94A7)
from __future__ import annotations
import json, subprocess, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const COPY = W0 + 0x3A94A7;
const LO = 0xA05000, HI = 0xA0A800;
const base = wx.base.add(LO);
const buf = new Uint8Array(base.readByteArray(HI-LO));
const out=[];
for (let i=0;i<buf.length-16;i++){
    if (buf[i]!==0x68) continue;
    const imm = buf[i+1]|(buf[i+2]<<8)|(buf[i+3]<<16)|(buf[i+4]<<24);
    for (let j=i+5;j<i+24 && j+4<buf.length;j++){
        if (buf[j]!==0xE8) continue;
        const rel = buf[j+1]|(buf[j+2]<<8)|(buf[j+3]<<16)|(buf[j+4]<<24);
        const rels = rel|0; const tgt = (LO + i + j + 5 + rels)>>>0;
        if (tgt === COPY){
            out.push({fn_rva:'0x'+(LO+i).toString(16), push:'0x'+(imm>>>0).toString(16),
                push_rva:'0x'+((imm>>>0)-W0).toString(16)});
            break;
        }
    }
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
sc.load(); import time; time.sleep(0.5)
items = res.get('items', [])
print(json.dumps(items, indent=2))
# test each wrapper
JS2 = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const CDN_VT = W0 + 0xB795B58;
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function snap(p){ const a=[]; for(let k=0;k<11;k++) a.push('0x'+u32(p.add(k*4)).toString(16)); return a; }
const fns = __FNS__;
const tested=[];
for (const rva of fns){
    const p = Memory.alloc(0x40);
    const rec = {rva:rva};
    try {
        new NativeFunction(wx.base.add(parseInt(rva,16)), 'void', ['pointer'], 'stdcall')(p);
        rec.ok=true; rec.vt='0x'+u32(p).toString(16); rec.cdn = u32(p)===CDN_VT; rec.snap=snap(p);
    } catch(e){ rec.err=e.message; }
    tested.push(rec);
}
send(tested);
""".replace('__FNS__', json.dumps([x['fn_rva'] for x in items[:12]]))
if items:
    sc2 = s.create_script(JS2)
    res2 = {}
    sc2.on('message', lambda m,_: res2.update({'t': m.get('payload',[])}) if m.get('type')=='send' else None)
    sc2.load(); time.sleep(0.5)
    print('\nTESTED:\n', json.dumps(res2.get('t',[]), indent=2))
    sc2.unload()
sc.unload(); s.detach()
