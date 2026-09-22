# M2c 深挖：完整反汇编 0x249CF20 + 找 CdnUploadParam 真 default_instance
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\m2c_dig_result.json")

JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const WX=wx.base, W0=WX.toUInt32(), SZ=wx.size;
const CDN_VT = W0 + 0xB795B58;
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||64);}catch(e){return null;} }
function inWx(v){ return v>=W0 && v<W0+SZ; }

// ============ 1) 反汇编 0x249CF20 完整 (直到 ret 或 0x600 字节) ============
function fullDisasm(rva, maxBytes){
    const out={rva:'0x'+rva.toString(16), insns:[], reads:{}, calls:[], strings:[]};
    let cur=WX.add(rva), walked=0;
    for (let n=0;n<1200 && walked<maxBytes;n++){
        let ins; try{ins=Instruction.parse(cur);}catch(e){break;}
        const line=('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr;
        out.insns.push(line);
        // 抓 [edx+X] / [ebp+8]+X 读取（edx=param at type5 entry, ebp+8 是 param&）
        const opStr = ins.opStr;
        const m = opStr.match(/dword ptr \[(edx|ebp \+ 8|ebp\+8|esi|edi)([+\-]0x[0-9a-f]+)?\]/i);
        if (m){
            const off = m[2] ? m[2].replace(/\s/g,'') : '+0';
            const key = m[1].replace(/\s/g,'')+off;
            out.reads[key] = (out.reads[key]||0)+1;
        }
        if (ins.mnemonic==='call'){
            out.calls.push({off:'+0x'+walked.toString(16), op:opStr});
        }
        for (const op of ins.operands||[]){
            if (op.type==='imm'){
                const v=op.value>>>0;
                if (inWx(v)){
                    const s=cstr(ptr(v), 80);
                    if (s && /^[\x20-\x7e]{6,}$/.test(s)) out.strings.push({off:'+0x'+walked.toString(16), s});
                }
            }
        }
        if (ins.mnemonic==='ret'){ out.ret_at='+0x'+walked.toString(16); break; }
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}
const type5 = fullDisasm(0x249CF20, 0x800);

// ============ 2) 扫模块 .data/.bss 找 vt=CdnUploadParam 的地址（真 default_instance）============
const patCdn = [(CDN_VT)&255,((CDN_VT>>>8)&255),((CDN_VT>>>16)&255),((CDN_VT>>>24)&255)]
    .map(b=>b.toString(16).padStart(2,'0')).join(' ');
const defaults=[];
for (const r of Process.enumerateRanges({protection:'rw-', coalesce:true})){
    const b = r.base.toUInt32();
    if (b+r.size < W0 || b >= W0+SZ) continue; // 只看 wxwork 模块内 rw
    let ms; try{ ms=Memory.scanSync(r.base, r.size, patCdn);}catch(e){continue;}
    for (const m of ms){
        const a = m.address;
        const dw=[]; for(let k=0;k<12;k++) dw.push('0x'+u32(a.add(k*4)).toString(16));
        defaults.push({va:a.toString(), rva:'0x'+(a.toUInt32()-W0).toString(16), section:'rw', dwords:dw});
    }
}
// 也扫 r-- （只读 .rdata）
for (const r of Process.enumerateRanges({protection:'r--', coalesce:true})){
    const b = r.base.toUInt32();
    if (b+r.size < W0 || b >= W0+SZ) continue;
    let ms; try{ ms=Memory.scanSync(r.base, r.size, patCdn);}catch(e){continue;}
    for (const m of ms){
        const a = m.address;
        // 过滤 .text（可执行）— rdata 应该 non-exec
        const dw=[]; for(let k=0;k<12;k++) dw.push('0x'+u32(a.add(k*4)).toString(16));
        defaults.push({va:a.toString(), rva:'0x'+(a.toUInt32()-W0).toString(16), section:'r', dwords:dw});
    }
}

// ============ 3) 找写 CdnUploadParam vtable 到 .data 的 InitAsDefaultInstance ============
// 特征：mov [imm32], vtable_va  → C7 05 <addr32> <vt32>
const textStart = W0 + 0x1000;
const textLimit = W0 + 0x9000000;
const inits=[];
for (const r of Process.enumerateRanges({protection:'r-x',coalesce:true})){
    if (r.base.toUInt32() < W0 || r.base.toUInt32() >= W0+SZ) continue;
    let ms; try{ ms=Memory.scanSync(r.base, r.size, patCdn);}catch(e){continue;}
    for (const m of ms.slice(0,50)){
        const site = m.address;
        // 检查前面 6 字节：C7 05 <addr>
        try {
            const pre = new Uint8Array(site.sub(6).readByteArray(6));
            if (pre[0]===0xC7 && pre[1]===0x05){
                const target = pre[2]|(pre[3]<<8)|(pre[4]<<16)|(pre[5]<<24);
                inits.push({
                    site_rva:'0x'+(site.toUInt32()-W0).toString(16),
                    kind:'mov [imm32], vt',
                    target_va:'0x'+(target>>>0).toString(16),
                    target_rva: inWx(target>>>0)?('0x'+((target>>>0)-W0).toString(16)):null,
                });
            }
        } catch(e){}
    }
}

send({type5:type5, defaults:defaults, inits:inits.slice(0,20)});
"""

pid = int(subprocess.run(["powershell","-Command",
    "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
    capture_output=True,text=True).stdout.strip())
import frida, time
s = frida.get_local_device().attach(pid)
sc = s.create_script(JS)
res = {}
def on_msg(m,_):
    if m.get('type')=='send': res.update(m.get('payload') or {})
    elif m.get('type')=='error': print('[!]', m.get('description'))
sc.on('message', on_msg)
sc.load(); time.sleep(3)
OUT.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding='utf-8')
sc.unload(); s.detach()

# 摘要
t5 = res.get('type5',{})
print(f"=== type5 @{t5.get('rva')} insns={len(t5.get('insns',[]))} ret={t5.get('ret_at')} ===")
print("reads offsets:", json.dumps(t5.get('reads',{}), indent=2))
print("\nstrings in type5:")
for s in (t5.get('strings') or [])[:10]:
    print(f"  {s['off']}: {s['s'][:80]}")
print(f"\n=== defaults found: {len(res.get('defaults',[]))} ===")
for d in (res.get('defaults') or [])[:5]:
    print(f"  {d['section']} {d['rva']}: {d['dwords'][:6]}")
print(f"\n=== inits found: {len(res.get('inits',[]))} ===")
for i in (res.get('inits') or [])[:8]:
    print(f"  site={i['site_rva']} target={i['target_rva']}")
print(f"\n→ {OUT.name}")
