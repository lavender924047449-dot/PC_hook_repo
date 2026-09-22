"""
反汇编两个候选构造函数 + VoiceRecord 附近的函数入口
"""
import json, sys, time, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent
CTOR_RVAS = [0x2b74832, 0x2b738a2]
VR_RVAS   = [0xab9be6f, 0xac14a50, 0xac14aac, 0xac22c0f, 0xac22c3b, 0xac25be8, 0xac25c18, 0xac2802b]

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
const W0 = wx.base.toUInt32();
send({t:'ready', base:'0x'+W0.toString(16)});

function readBytes(va, n){
    try{ return Array.from(new Uint8Array(ptr(va).readByteArray(n))); }
    catch(e){ return []; }
}
function u8(p){ try{ return p.readU8(); } catch(e){ return 0; } }

// walk backward from addr to find prologue (55 8B EC)
function findFuncStart(va){
    for(let d=0;d<=1024;d++){
        const a=(va-d)>>>0;
        const b0=u8(ptr(a)), b1=u8(ptr(a+1)), b2=u8(ptr(a+2));
        if(b0===0x55&&b1===0x8b&&b2===0xec) return {va:'0x'+a.toString(16), rva:'0x'+(a-W0).toString(16), delta:d};
        if(b0===0x8b&&b1===0xff&&b2===0x55) return {va:'0x'+a.toString(16), rva:'0x'+(a-W0).toString(16), delta:d, hp:true};
    }
    return null;
}

rpc.exports = {
    disasmRvas: function(rvas){
        const out = [];
        for(const rva of rvas){
            const va = (W0+rva)>>>0;
            const bytes = readBytes(va, 192);
            out.push({rva:'0x'+rva.toString(16), va:'0x'+va.toString(16),
                      bytes_hex: bytes.map(b=>b.toString(16).padStart(2,'0')).join(' ')});
        }
        return out;
    },
    findVoiceRecordFuncs: function(str_rvas){
        // Each VoiceRecord string is referenced from code via PUSH imm32
        // Scan code section for PUSH <str_rva_va> patterns, then find func starts
        const results = [];
        for(const str_rva of str_rvas){
            const str_va = (W0+str_rva)>>>0;
            const pat = [(str_va&0xff),(str_va>>8&0xff),(str_va>>16&0xff),(str_va>>24&0xff)]
                        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
            let hits;
            try{ hits = Memory.scanSync(wx.base, wx.size, pat); }
            catch(e){ continue; }
            for(const h of hits){
                const ref_va = h.address.toUInt32();
                const ref_rva = ref_va - W0;
                if(ref_rva < 0x1000 || ref_rva > 0x25000000) continue;
                const prev = u8(ptr(ref_va-1));
                if(prev !== 0x68) continue; // must be PUSH imm32
                const fn = findFuncStart(ref_va);
                if(!fn) continue;
                results.push({
                    str_rva: '0x'+str_rva.toString(16),
                    ref_rva: '0x'+ref_rva.toString(16),
                    func_rva: fn.rva,
                    func_va: fn.va,
                    delta: fn.delta,
                    bytes_hex: readBytes(parseInt(fn.va),128).map(b=>b.toString(16).padStart(2,'0')).join(' ')
                });
            }
        }
        return results;
    }
};
"""

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    pid = get_pid()
    if not pid: print("[!] WXWork not running"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script  = session.create_script(FRIDA_JS)
    ready   = {"v": False, "base": None}

    def on_msg(m, _d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
                ready["base"] = p.get("base")
        elif m.get("type") == "error":
            print("  [ERR]", m.get("description"))

    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)
    print(f"[*] wxwork.exe base = {ready['base']}")

    # 1. 反汇编两个构造函数
    print("\n=== 构造函数反汇编 ===")
    dis = script.exports_sync.disasm_rvas(CTOR_RVAS)
    for d in dis:
        print(f"\n[func_rva={d['rva']}  va={d['va']}]")
        # print 32-byte rows
        b = d["bytes_hex"].split()
        for row in range(0, min(len(b), 64), 16):
            chunk = b[row:row+16]
            print(f"  +{row:02x}:  {' '.join(chunk)}")

    # 2. VoiceRecord 函数入口
    print("\n=== VoiceRecord 函数入口 ===")
    vr_funcs = script.exports_sync.find_voice_record_funcs(VR_RVAS)
    print(f"  找到 {len(vr_funcs)} 个引用函数")
    unique = {}
    for f in vr_funcs:
        if f["func_rva"] not in unique:
            unique[f["func_rva"]] = f
    for rva, f in list(unique.items())[:15]:
        print(f"\n  [str_rva={f['str_rva']} → func_rva={f['func_rva']}  delta={f['delta']}]")
        b = f["bytes_hex"].split()
        print(f"    bytes: {' '.join(b[:48])}")

    try: script.unload(); session.detach()
    except Exception: pass

    out = OUT_DIR / "voice_ctor_disasm.json"
    out.write_text(json.dumps({"pid":pid, "ctors":dis, "vr_funcs":vr_funcs},
                               ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
