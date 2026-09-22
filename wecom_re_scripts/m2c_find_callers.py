# m2c_find_callers.py — 扫 E8 rel32，找 CdnUploadFileTask ctor / CdnUploadParam ctor 的调用者
# 不 hook。

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

# 上一刀实证 RVA
TASK_CTOR = 0x8F790C2
PARAM_CTOR = 0xA08C56
PARAM_DTOR = 0xA08B83
WIN_SLOTS = [0x24998A0, 0xB964758, 0x2499660, 0xB9647A0, 0x24996D0]

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
const WX = wx.base, SZ = wx.size, W0 = WX.toUInt32();
send({t:'info', msg:'wx='+WX});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function cstr(p,n){ try { return p.readCString(n||120); } catch(e){ return null; } }

function findPrologue(site){
    for (let b=0;b<=0x120;b++){
        const p=site.sub(b);
        try {
            const b0=p.readU8(), b1=p.add(1).readU8();
            if ((b0===0x55 && (b1===0x8b || b1===0x89)) || (b0===0x56 && b1===0x8b)) return p;
        } catch(e){ return null; }
    }
    return null;
}

function scanCallsTo(targetRva, maxHits){
    const target = WX.add(targetRva).toUInt32();
    const hits=[];
    // 扫整个模块找 E8 rel32
    const ranges = [{base:WX, size:SZ}];
    for (let ri=0; ri<ranges.length; ri++){
        const base=ranges[ri].base, size=ranges[ri].size;
        // 分段扫，避免一次 256MB
        const CHUNK=0x200000;
        for (let off=0; off<size; off+=CHUNK){
            const n = Math.min(CHUNK, size-off);
            let buf;
            try { buf = new Uint8Array(base.add(off).readByteArray(n)); }
            catch(e){ continue; }
            for (let i=0; i<n-4; i++){
                if (buf[i] !== 0xe8) continue;
                const rel = buf[i+1] | (buf[i+2]<<8) | (buf[i+3]<<16) | (buf[i+4]<<24);
                const siteVA = W0 + off + i;
                const dest = (siteVA + 5 + rel) >>> 0;
                if (dest !== target) continue;
                const site = ptr(siteVA);
                const fn = findPrologue(site);
                hits.push({
                    site_rva:'0x'+(siteVA-W0).toString(16),
                    fn_rva: fn?('0x'+(fn.toUInt32()-W0).toString(16)):null,
                    fn: fn?fn.toString():null
                });
                if (hits.length >= maxHits) return hits;
            }
        }
    }
    return hits;
}

function disasm(fnRva, maxBytes){
    const fn = WX.add(fnRva).toUInt32();
    const out={rva:'0x'+fnRva.toString(16), insns:[], strings:[], calls:[]};
    let cur=ptr(fn), walked=0;
    for (let n=0;n<220 && walked<maxBytes;n++){
        let ins; try { ins=Instruction.parse(cur);} catch(e){ break; }
        out.insns.push(ins.mnemonic+' '+ins.opStr);
        if (ins.mnemonic==='call'){
            out.calls.push({off:walked, op:ins.opStr});
        }
        for (let i=0;i<ins.operands.length;i++){
            const op=ins.operands[i];
            if (op.type!=='imm') continue;
            const v=op.value>>>0;
            if (v>=W0 && v<W0+SZ){
                const s=cstr(ptr(v),140);
                if (s && s.length>=4 && s.length<140 && /^[\x20-\x7e]+$/.test(s))
                    out.strings.push(s);
            }
        }
        if (ins.mnemonic==='ret') break;
        walked+=ins.size; cur=cur.add(ins.size);
    }
    return out;
}

rpc.exports = {
    run: function(cfgJson){
        const cfg=JSON.parse(cfgJson);
        send({t:'info', msg:'scan calls → CdnUploadFileTask ctor'});
        const taskCallers = scanCallsTo(cfg.task_ctor, 40);
        send({t:'info', msg:'task callers='+taskCallers.length});

        send({t:'info', msg:'scan calls → CdnUploadParam ctor'});
        const paramCallers = scanCallsTo(cfg.param_ctor, 60);
        send({t:'info', msg:'param callers='+paramCallers.length});

        const uniqueTaskFns = {};
        for (let i=0;i<taskCallers.length;i++){
            const k=taskCallers[i].fn_rva || taskCallers[i].site_rva;
            if (!uniqueTaskFns[k]) uniqueTaskFns[k]=taskCallers[i];
        }
        const taskFnDisasm=[];
        const keys=Object.keys(uniqueTaskFns);
        for (let i=0;i<keys.length && i<12;i++){
            const rva=parseInt(keys[i],16);
            send({t:'info', msg:'disasm task-caller '+keys[i]});
            taskFnDisasm.push(disasm(rva, 0x280));
        }

        const uniqueParamFns={};
        for (let i=0;i<paramCallers.length;i++){
            const k=paramCallers[i].fn_rva || paramCallers[i].site_rva;
            if (!uniqueParamFns[k]) uniqueParamFns[k]=paramCallers[i];
        }
        const paramFnSummary=[];
        const pkeys=Object.keys(uniqueParamFns);
        for (let i=0;i<pkeys.length && i<20;i++){
            const rva=parseInt(pkeys[i],16);
            const d=disasm(rva, 0x180);
            paramFnSummary.push({rva:d.rva, strings:d.strings.slice(0,8), n_insns:d.insns.length, calls:d.calls.slice(0,8)});
        }

        send({t:'info', msg:'disasm WinMember slots + param ctor'});
        const win=[];
        for (let i=0;i<cfg.win_slots.length;i++){
            win.push(disasm(cfg.win_slots[i], 0x200));
        }
        const paramCtor = disasm(cfg.param_ctor, 0x160);

        return {
            task_callers:taskCallers,
            param_callers:paramCallers,
            task_fn_disasm:taskFnDisasm,
            param_fn_summary:paramFnSummary,
            win_slots:win,
            param_ctor:paramCtor
        };
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
    print(f"[*] callers PID={pid}")

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

    t0 = time.monotonic()
    rec = script.exports_sync.run(json.dumps({
        "task_ctor": TASK_CTOR,
        "param_ctor": PARAM_CTOR,
        "win_slots": WIN_SLOTS,
    }))
    print(f"[+] {time.monotonic()-t0:.1f}s")
    try:
        script.unload()
        session.detach()
    except Exception:
        pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m2c_find_callers_{ts}.json"
    text = json.dumps(rec, ensure_ascii=False, indent=2)
    out.write_text(text, encoding="utf-8")
    (OUT_DIR / "m2c_find_callers.json").write_text(text, encoding="utf-8")

    print(f"\n[CdnUploadFileTask ctor callers] {len(rec.get('task_callers') or [])}")
    for c in rec.get("task_callers") or []:
        print(f"  {c['site_rva']}  fn {c.get('fn_rva')}")

    print("\n[task-caller functions]")
    for d in rec.get("task_fn_disasm") or []:
        print(f"  ---- {d['rva']} strings={d.get('strings')[:8]}")
        for ins in (d.get("insns") or [])[:18]:
            print(f"      {ins}")

    print(f"\n[CdnUploadParam ctor callers] {len(rec.get('param_callers') or [])}")
    for s in rec.get("param_fn_summary") or []:
        print(f"  {s['rva']} n={s['n_insns']} str={s.get('strings')[:6]}")

    print("\n[param ctor 0xa08c56]")
    for ins in (rec.get("param_ctor") or {}).get("insns") or []:
        print(f"      {ins}")

    print("\n[WinMember slot strings]")
    for d in rec.get("win_slots") or []:
        print(f"  {d['rva']} str={d.get('strings')[:6]}")

    print(f"[+] → {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
