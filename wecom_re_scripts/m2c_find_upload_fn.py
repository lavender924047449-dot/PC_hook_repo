# m2c_find_upload_fn.py — 用 CdnUploadFileTask / CdnUploadParam 立即数反查 CdnUploadFile
# 不 hook。

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

# RVA
IMPL0 = 0xB48FAB4
IMPL1 = 0xB48FAC0
WIN = 0xAB69988
PARAM_VT = 0xB795B58
TASK_VT = 0xB48CA88
PARAM_CTORS = [0xA08B00, 0xA08B83, 0xA08C56]

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
const WX = wx.base, SZ = wx.size, W0 = WX.toUInt32(), W1 = W0+SZ;
send({t:'info', msg:'wx='+WX});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function cstr(p,n){ try { return p.readCString(n||160); } catch(e){ return null; } }
function inWx(v){ return v>=W0 && v<W1; }
function pat(v){
    return [(v&255),((v>>>8)&255),((v>>>16)&255),((v>>>24)&255)]
        .map(function(b){return b.toString(16).padStart(2,'0');}).join(' ');
}

function disasm(fn, maxBytes){
    const out = {insns:[], strings:[], imms:[]};
    if (!inWx(fn)) return out;
    let cur = ptr(fn), walked=0;
    for (let n=0; n<160 && walked<maxBytes; n++){
        let ins; try { ins = Instruction.parse(cur); } catch(e){ break; }
        if (n<24) out.insns.push(ins.mnemonic+' '+ins.opStr);
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            if (!inWx(v)) continue;
            out.imms.push('0x'+v.toString(16));
            const s=cstr(ptr(v),140);
            if (s && s.length>=4 && s.length<140) out.strings.push(s);
        }
        if (ins.mnemonic==='ret') break;
        walked += ins.size; cur=cur.add(ins.size);
    }
    return out;
}

function scanImm(immVA, maxHits){
    let refs;
    try { refs = Memory.scanSync(WX, SZ, pat(immVA)); }
    catch(e){ return []; }
    const out=[];
    for (let i=0;i<refs.length && out.length<maxHits;i++){
        const site=refs[i].address;
        let fn=null;
        for (let b=0;b<=0x80;b++){
            const p=site.sub(b);
            try {
                const b0=p.readU8(), b1=p.add(1).readU8();
                if ((b0===0x55&&(b1===0x8b||b1===0x89))||(b0===0x56&&b1===0x8b)||(b0===0x53&&b1===0x56)){
                    fn=p; break;
                }
            } catch(e){ break; }
        }
        out.push({
            site:'0x'+site.toUInt32().toString(16),
            site_rva:'0x'+(site.toUInt32()-W0).toString(16),
            fn: fn?fn.toString():null,
            fn_rva: fn?('0x'+(fn.toUInt32()-W0).toString(16)):null
        });
    }
    return out;
}

function slotHasImm(fnVA, watch){
    if (!inWx(fnVA)) return {hit:false};
    let cur=ptr(fnVA), walked=0;
    const strings=[];
    for (let n=0;n<200 && walked<0x500;n++){
        let ins; try { ins=Instruction.parse(cur);} catch(e){ break; }
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            for (let k=0;k<watch.length;k++){
                if (v===watch[k]) return {hit:true, imm:'0x'+v.toString(16), off:walked, strings:strings};
            }
            if (inWx(v)){
                const s=cstr(ptr(v),80);
                if (s && /CdnUpload|upload_cdn|silk|Voice|file_path|file_type/i.test(s)) strings.push(s);
            }
        }
        if (ins.mnemonic==='ret') break;
        walked+=ins.size; cur=cur.add(ins.size);
    }
    if (strings.length) return {hit:true, imm:null, strings:strings};
    return {hit:false};
}

rpc.exports = {
    run: function(cfgJson){
        const cfg=JSON.parse(cfgJson);
        const taskVA = WX.add(cfg.task_vt).toUInt32();
        const paramVA = WX.add(cfg.param_vt).toUInt32();
        const watch=[taskVA, paramVA];
        for (let i=0;i<cfg.ctors.length;i++) watch.push(WX.add(cfg.ctors[i]).toUInt32());

        send({t:'info', msg:'disasm param ctors'});
        const ctors=[];
        for (let i=0;i<cfg.ctors.length;i++){
            const rva=cfg.ctors[i];
            const fn=WX.add(rva).toUInt32();
            const d=disasm(fn, 0x120);
            ctors.push({rva:'0x'+rva.toString(16), va:'0x'+fn.toString(16), ...d});
        }

        send({t:'info', msg:'scan .text for CdnUploadFileTask vtable imm'});
        const taskXrefs = scanImm(taskVA, 40);

        send({t:'info', msg:'scan .text for CdnUploadParam vtable imm'});
        const paramXrefs = scanImm(paramVA, 30);

        send({t:'info', msg:'scan FileServiceImpl slots 0..220'});
        const implHits=[];
        function scanVt(name, rva, n){
            const vt=WX.add(rva);
            for (let i=0;i<n;i++){
                const fn=u32(vt.add(i*4));
                const h=slotHasImm(fn, watch);
                if (h.hit){
                    implHits.push({vt:name, slot:i, fn:'0x'+fn.toString(16),
                        rva: inWx(fn)?('0x'+(fn-W0).toString(16)):null,
                        imm:h.imm, strings:h.strings||[]});
                }
            }
        }
        scanVt('FileServiceImpl_0', cfg.impl0, 220);
        scanVt('FileServiceImpl_1', cfg.impl1, 80);
        scanVt('FileServiceWinMember', cfg.win, 16);

        send({t:'info', msg:'dump singletons'});
        const objs={};
        const addrs=cfg.objs||{};
        const names=Object.keys(addrs);
        for (let i=0;i<names.length;i++){
            const a=ptr(addrs[names[i]]);
            const dwords=[];
            for (let k=0;k<24;k++) dwords.push('0x'+u32(a.add(k*4)).toString(16));
            objs[names[i]]={addr:addrs[names[i]], dwords:dwords};
        }

        // WinMember 前 8 槽反汇编
        const winSlots=[];
        const wvt=WX.add(cfg.win);
        for (let i=0;i<8;i++){
            const fn=u32(wvt.add(i*4));
            winSlots.push({i:i, fn:'0x'+fn.toString(16),
                rva:inWx(fn)?('0x'+(fn-W0).toString(16)):null,
                disasm: disasm(fn, 0x80)});
        }

        return {
            ctors:ctors, task_xrefs:taskXrefs, param_xrefs:paramXrefs,
            impl_hits:implHits, objs:objs, win_slots:winSlots
        };
    }
};
send({t:'ready'});
"""


def _pid():
    r = subprocess.run(
        ["powershell", "-Command",
         "Get-Process WXWork -ErrorAction SilentlyContinue | "
         "Sort-Object WorkingSet64 -Descending | Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True, encoding="utf-8",
    )
    s = r.stdout.strip()
    return int(s) if s else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    args = ap.parse_args()
    pid = args.pid or _pid()
    if not pid:
        print("[!] no WXWork")
        return 1

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

    cfg = {
        "impl0": IMPL0, "impl1": IMPL1, "win": WIN,
        "param_vt": PARAM_VT, "task_vt": TASK_VT, "ctors": PARAM_CTORS,
        "objs": {
            "FileServiceWinMember": "0x2b5983c0",
            "FileServiceImpl_0": "0x24b94bc4",
            "FileServiceImpl_1": "0x24b94bd0",
        },
    }
    t0 = time.monotonic()
    rec = script.exports_sync.run(json.dumps(cfg))
    print(f"[+] {time.monotonic()-t0:.1f}s")
    try:
        script.unload()
        session.detach()
    except Exception:
        pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m2c_find_upload_fn_{ts}.json"
    out.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT_DIR / "m2c_find_upload_fn.json").write_text(
        json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n[CdnUploadParam ctors]")
    for c in rec.get("ctors") or []:
        print(f"  {c['rva']} strings={c.get('strings')[:6]}")
        for ins in (c.get("insns") or [])[:8]:
            print(f"      {ins}")

    print(f"\n[CdnUploadFileTask vtable xrefs] {len(rec.get('task_xrefs') or [])}")
    for x in (rec.get("task_xrefs") or [])[:20]:
        print(f"  site {x['site_rva']}  fn {x.get('fn_rva')}")

    print(f"\n[CdnUploadParam vtable xrefs] {len(rec.get('param_xrefs') or [])}")
    for x in (rec.get("param_xrefs") or [])[:15]:
        print(f"  site {x['site_rva']}  fn {x.get('fn_rva')}")

    print(f"\n[vtable slot hits] {len(rec.get('impl_hits') or [])}")
    for h in rec.get("impl_hits") or []:
        print(f"  {h['vt']}[{h['slot']}] {h.get('rva')} imm={h.get('imm')} str={h.get('strings')[:4]}")

    print("\n[WinMember slots 0..7]")
    for s in rec.get("win_slots") or []:
        print(f"  [{s['i']}] {s.get('rva')} str={s.get('disasm',{}).get('strings')[:4]}")

    print(f"[+] → {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
