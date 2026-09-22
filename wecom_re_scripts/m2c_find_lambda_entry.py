# m2c_find_lambda_entry.py — 用 CdnUploadFile 函数内 lambda 的 RTTI 反查入口
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\m2c_lambda_entry.json")

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m => m.name.toLowerCase()==='wxwork.exe')[0];
const WX=wx.base, W0=WX.toUInt32(), SZ=wx.size;
send({t:'info', msg:'wx='+WX});
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function cstr(p,n){ try{return p.readCString(n||200);}catch(e){return null;} }
function pat(v){
    return [(v&255),((v>>>8)&255),((v>>>16)&255),((v>>>24)&255)]
        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
}
function strpat(s){
    return Array.from(s).map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
}

function disasm(va, maxBytes){
    const out={va:'0x'+(va>>>0).toString(16), rva:'0x'+((va-W0)>>>0).toString(16), insns:[], strings:[]};
    let cur=ptr(va), walked=0;
    for (let n=0;n<200 && walked<maxBytes;n++){
        let ins; try{ins=Instruction.parse(cur);}catch(e){break;}
        out.insns.push(('+0x'+walked.toString(16)).padEnd(8)+ins.mnemonic+' '+ins.opStr);
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            if (v>=W0 && v<W0+SZ){
                const s=cstr(ptr(v),160);
                if (s && /^[\x20-\x7e]{4,140}$/.test(s)) out.strings.push(s);
            }
        }
        if (ins.mnemonic==='ret') break;
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}

function findPrologue(site){
    for (let b=0;b<=0x200;b++){
        const p=site.sub(b);
        try{
            const b0=p.readU8(), b1=p.add(1).readU8();
            if (b0===0x55 && (b1===0x8b || b1===0x89)) return p;
            if (b0===0x6a && b1===0xff) { // push -1  SEH prologue often after
                const b2=p.add(2).readU8();
                if (b2===0x68) return p;
            }
        }catch(e){return null;}
    }
    return null;
}

rpc.exports = {
    run: function(){
        const needle = 'CdnUploadFile@FileService@@';
        send({t:'info', msg:'scan '+needle});
        let nameHits;
        try { nameHits = Memory.scanSync(WX, SZ, strpat(needle)); }
        catch(e){ return {err:e.message}; }
        const names=[];
        for (let i=0;i<nameHits.length && i<8;i++){
            const p=nameHits[i].address;
            names.push({va:p.toString(), rva:'0x'+(p.toUInt32()-W0).toString(16), cstr:cstr(p.sub(32),220)});
        }

        // 对每个 name hit，把它当成 TypeDescriptor.name 的一部分，
        // 先找附近的 ".?AV" 起点，再扫 dword xref
        const xrefs=[];
        for (let i=0;i<nameHits.length && i<6;i++){
            let start=nameHits[i].address;
            // 向前最多 80 字节找 .?AV
            let tdName=null;
            for (let b=0;b<=80;b++){
                const p=start.sub(b);
                try{
                    if (p.readU8()===0x2e && p.add(1).readU8()===0x3f &&
                        p.add(2).readU8()===0x41 && p.add(3).readU8()===0x56){
                        tdName=p; break;
                    }
                }catch(e){break;}
            }
            if (!tdName) continue;
            const td=tdName.sub(8);
            let refs;
            try { refs = Memory.scanSync(WX, SZ, pat(td.toUInt32())); }
            catch(e){ continue; }
            for (let j=0;j<refs.length && j<20;j++){
                const site=refs[j].address;
                const fn=findPrologue(site);
                xrefs.push({
                    td:td.toString(),
                    td_name:cstr(tdName,180),
                    site_rva:'0x'+(site.toUInt32()-W0).toString(16),
                    fn_rva: fn?('0x'+(fn.toUInt32()-W0).toString(16)):null,
                    fn: fn?fn.toString():null
                });
            }
        }

        // 去重 fn 并反汇编
        const seen={};
        const fns=[];
        for (let i=0;i<xrefs.length;i++){
            const k=xrefs[i].fn_rva;
            if (!k || seen[k]) continue;
            seen[k]=1;
            send({t:'info', msg:'disasm '+k});
            fns.push(disasm(parseInt(xrefs[i].fn,16), 0x280));
        }

        // FileService 抽象 vtable 前 16 槽
        const absRvas=[0xab698e4,0xab6990c,0xab69918,0xab69924];
        const abs=[];
        for (let a=0;a<absRvas.length;a++){
            const vt=WX.add(absRvas[a]);
            const slots=[];
            for (let i=0;i<16;i++){
                const fn=u32(vt.add(i*4));
                const rva=(fn>W0&&fn<W0+SZ)?(fn-W0):0;
                let hint=null;
                if (rva){
                    const d=disasm(fn, 0x60);
                    hint={rva:'0x'+rva.toString(16), strings:d.strings.slice(0,4), first:(d.insns||[]).slice(0,6)};
                }
                slots.push({i:i, fn:'0x'+fn.toString(16), hint:hint});
            }
            abs.push({rva:'0x'+absRvas[a].toString(16), slots:slots});
        }

        return {names:names, xrefs:xrefs, fns:fns, file_service_vtables:abs};
    }
};
send({t:'ready'});
"""


def main() -> int:
    r = subprocess.run(
        ["powershell", "-Command",
         "Get-Process WXWork -ErrorAction SilentlyContinue | "
         "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True, encoding="utf-8",
    )
    pid = int(r.stdout.strip()) if r.stdout.strip() else None
    if not pid:
        print("[!] no WXWork")
        return 1
    print(f"[*] lambda entry PID={pid}")
    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_msg(msg, _d):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "info":
                print(f"    [js] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_msg)
    script.load()
    for _ in range(40):
        if ready["v"]:
            break
        time.sleep(0.1)

    rec = script.exports_sync.run()
    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    OUT.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n[name hits] {len(rec.get('names') or [])}")
    for n in rec.get("names") or []:
        print(f"  {n.get('rva')} {n.get('cstr','')[:80]}")
    print(f"[xrefs] {len(rec.get('xrefs') or [])}")
    for x in rec.get("xrefs") or []:
        print(f"  site {x.get('site_rva')} fn {x.get('fn_rva')}")
    print("\n[functions]")
    for d in rec.get("fns") or []:
        print(f"\n==== {d.get('rva')} str={d.get('strings')[:6]} ====")
        for ins in (d.get("insns") or [])[:28]:
            print(f"  {ins}")
    print("\n[FileService vtable slot0-8]")
    for vt in rec.get("file_service_vtables") or []:
        print(f"  {vt['rva']}")
        for s in (vt.get("slots") or [])[:9]:
            h = s.get("hint") or {}
            print(f"    [{s['i']}] {h.get('rva')} {h.get('strings')[:3]} {(h.get('first') or [])[:2]}")
    print(f"[+] → {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
