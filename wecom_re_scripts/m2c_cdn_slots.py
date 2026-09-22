# m2c_cdn_slots.py — M2c 第二刀：用已确认 vtable RVA 挖 CdnUploadFile 槽 + 单例 + ctor
# 不 hook。FileService 精确 RTTI 在 packed 串里，第一刀 exact cstring 会漏；本脚本直接用 RVA。

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

# 2026-09-13 · PID 21768 · wx=0x1c0000 · find_vtable_by_class.py
VTABLES = {
    "FileService_abs_a": 0xAB698E4,   # 多处 0x3bdde0 = 疑似纯虚
    "FileService_abs_b": 0xAB6990C,
    "FileService_abs_c": 0xAB69918,
    "FileService_abs_d": 0xAB69924,
    "FileService_logic": 0xB48F918,   # FileService@logic@wework
    "FileServiceWinMember": 0xAB69988,
    "FileServiceImpl_0": 0xB48FAB4,
    "FileServiceImpl_1": 0xB48FAC0,
    "CdnUploadParam": 0xB795B58,
    "CdnUploadFileTask": 0xB48CA88,
}

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base;
const WXSIZE = wx.size;
const WX0 = WXBASE.toUInt32();
const WX1 = WX0 + WXSIZE;
send({t:'info', msg:'wx base=' + WXBASE});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function cstr(p, n){ try { return p.readCString(n || 160); } catch(e){ return null; } }
function inWx(v){ return v >= WX0 && v < WX1; }
function u32pat(v){
    return [(v&0xff),((v>>>8)&0xff),((v>>>16)&0xff),((v>>>24)&0xff)]
        .map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' ');
}

function dumpSlots(rva, n){
    const vt = WXBASE.add(rva);
    const out = [];
    for (let i = 0; i < n; i++){
        const fn = u32(vt.add(i*4));
        out.push({i:i, fn:'0x'+fn.toString(16), rva: inWx(fn) ? ('0x'+(fn-WX0).toString(16)) : null});
    }
    return out;
}

function scanFn(fnVA, maxBytes, watchImm){
    const r = {strings:[], imm:[], insns:[]};
    if (!inWx(fnVA)) return r;
    let cur = ptr(fnVA);
    let walked = 0;
    for (let n = 0; n < 120 && walked < maxBytes; n++){
        let ins;
        try { ins = Instruction.parse(cur); } catch(e){ break; }
        if (n < 6) r.insns.push(ins.mnemonic + ' ' + ins.opStr);
        for (let oi = 0; oi < ins.operands.length; oi++){
            const op = ins.operands[oi];
            if (op.type !== 'imm') continue;
            const v = op.value >>> 0;
            if (!inWx(v)) continue;
            const s = cstr(ptr(v), 140);
            if (s && s.length >= 4 && s.length < 120) r.strings.push(s);
            for (let k = 0; k < watchImm.length; k++){
                if (v === watchImm[k]) r.imm.push('0x'+v.toString(16));
            }
        }
        if (ins.mnemonic === 'ret') break;
        walked += ins.size;
        cur = cur.add(ins.size);
    }
    return r;
}

function heapHits(rva, maxHits){
    const pat = u32pat(WXBASE.add(rva).toUInt32());
    const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
    const addrs = [];
    for (let i = 0; i < ranges.length && addrs.length < maxHits; i++){
        const rg = ranges[i];
        if (rg.file) continue;
        if (rg.size < 0x1000 || rg.size > 0x8000000) continue;
        let ms;
        try { ms = Memory.scanSync(rg.base, rg.size, pat); } catch(e){ continue; }
        for (let j = 0; j < ms.length && addrs.length < maxHits; j++) addrs.push(ms[j].address.toString());
    }
    return addrs;
}

function findVptrWrites(vtableRva, maxHits){
    const vtVA = WXBASE.add(vtableRva).toUInt32();
    let refs;
    try { refs = Memory.scanSync(WXBASE, WXSIZE, u32pat(vtVA)); }
    catch(e){ return []; }
    const out = [];
    for (let i = 0; i < refs.length && out.length < maxHits; i++){
        const site = refs[i].address;
        let fn = null;
        for (let back = 0; back <= 0x50; back++){
            const p = site.sub(back);
            try {
                const b0 = p.readU8(), b1 = p.add(1).readU8();
                if ((b0===0x55 && (b1===0x8b || b1===0x89)) || (b0===0x56 && b1===0x8b) || (b0===0x53 && b1===0x56)){
                    fn = p; break;
                }
            } catch(e){ break; }
        }
        out.push({
            site_rva: '0x'+(site.toUInt32()-WX0).toString(16),
            fn_rva: fn ? ('0x'+(fn.toUInt32()-WX0).toString(16)) : null,
            fn: fn ? fn.toString() : null,
        });
    }
    return out;
}

rpc.exports = {
    run: function(cfgJson){
        const cfg = JSON.parse(cfgJson);
        const vtables = cfg.vtables;
        const slotN = cfg.slot_n || 64;
        const watchImm = [];
        const names = Object.keys(vtables);
        for (let i = 0; i < names.length; i++){
            watchImm.push(WXBASE.add(vtables[names[i]]).toUInt32());
        }

        const analyzed = {};
        for (let i = 0; i < names.length; i++){
            const name = names[i];
            const rva = vtables[name];
            send({t:'info', msg:'slots '+name+' 0x'+rva.toString(16)});
            const slots = dumpSlots(rva, slotN);
            const interesting = [];
            for (let s = 0; s < slots.length; s++){
                const fn = parseInt(slots[s].fn, 16);
                const h = scanFn(fn, 0x300, watchImm);
                const joined = (h.strings||[]).join('\n');
                const hit = h.imm.length > 0 ||
                    /CdnUpload|upload_cdn|CdnUploadParam|\.silk|Cache\\Voice|file_path|file_type|CdnUploadFileTask|begin uploading/i.test(joined);
                if (hit){
                    interesting.push({
                        i:s, fn:slots[s].fn, rva:slots[s].rva,
                        strings:h.strings.slice(0,16), imm:h.imm, insns:h.insns
                    });
                }
            }
            analyzed[name] = {rva:'0x'+rva.toString(16), interesting:interesting, slots:slots};
        }

        send({t:'info', msg:'heap scan'});
        const heap = {};
        const heapNames = ['FileServiceWinMember','FileServiceImpl_0','FileServiceImpl_1','FileService_logic','FileService_abs_d'];
        for (let i = 0; i < heapNames.length; i++){
            heap[heapNames[i]] = heapHits(vtables[heapNames[i]], 12);
        }

        send({t:'info', msg:'param ctor'});
        const paramCtors = findVptrWrites(vtables.CdnUploadParam, 16);

        // 对比 FileService_abs_d 与 WinMember 的槽差异（实现覆盖点）
        const abs = analyzed.FileService_abs_d.slots;
        const win = analyzed.FileServiceWinMember.slots;
        const diffs = [];
        const n = Math.min(abs.length, win.length);
        for (let i = 0; i < n; i++){
            if (abs[i].fn !== win[i].fn){
                const h = scanFn(parseInt(win[i].fn,16), 0x280, watchImm);
                diffs.push({
                    i:i, abs:abs[i].fn, win:win[i].fn, win_rva:win[i].rva,
                    strings:h.strings.slice(0,10), imm:h.imm, insns:h.insns
                });
            }
        }

        return {analyzed:analyzed, heap:heap, param_ctors:paramCtors, win_vs_abs_diffs:diffs};
    }
};
send({t:'ready'});
"""


def _pid() -> int | None:
    r = subprocess.run(
        ["powershell", "-Command",
         "Get-Process WXWork -ErrorAction SilentlyContinue | "
         "Sort-Object WorkingSet64 -Descending | "
         "Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True, encoding="utf-8",
    )
    s = r.stdout.strip()
    return int(s) if s else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--slots", type=int, default=64)
    args = ap.parse_args()
    pid = args.pid or _pid()
    if not pid:
        print("[!] no WXWork")
        return 1
    print(f"[*] slots/heap/ctor PID={pid}")

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
    rec = script.exports_sync.run(json.dumps({"vtables": VTABLES, "slot_n": args.slots}))
    print(f"[+] done in {time.monotonic()-t0:.1f}s")
    try:
        script.unload()
        session.detach()
    except Exception:
        pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m2c_cdn_slots_{ts}.json"
    cache = OUT_DIR / "m2c_cdn_slots.json"
    text = json.dumps(rec, ensure_ascii=False, indent=2)
    out.write_text(text, encoding="utf-8")
    cache.write_text(text, encoding="utf-8")

    print()
    print("[heap]")
    for k, addrs in (rec.get("heap") or {}).items():
        print(f"  {k}: {len(addrs)}  {addrs[:6]}")

    print()
    print("[interesting slots]")
    for name, block in (rec.get("analyzed") or {}).items():
        hits = block.get("interesting") or []
        if not hits:
            continue
        print(f"  {name} ({len(hits)})")
        for h in hits:
            print(f"    [{h['i']}] {h.get('rva')} imm={h.get('imm')} str={h.get('strings')[:5]}")

    print()
    print(f"[WinMember vs FileService_abs_d diffs] {len(rec.get('win_vs_abs_diffs') or [])}")
    for d in (rec.get("win_vs_abs_diffs") or [])[:24]:
        print(f"  slot[{d['i']}] win={d.get('win_rva')} imm={d.get('imm')} str={d.get('strings')[:4]}")

    print()
    print(f"[CdnUploadParam ctor cand] {len(rec.get('param_ctors') or [])}")
    for c in (rec.get("param_ctors") or [])[:10]:
        print(f"  site {c.get('site_rva')}  fn {c.get('fn_rva')}")

    print(f"[+] → {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
