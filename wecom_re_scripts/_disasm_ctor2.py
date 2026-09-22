"""
扩展反汇编 + 找 VoiceRecord 字符串的正确代码引用方式
"""
import json, sys, time, subprocess
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
const W0 = wx.base.toUInt32();
const WXSIZE = wx.size;
send({t:'ready', base:'0x'+W0.toString(16)});

function rb(va,n){ try{return Array.from(new Uint8Array(ptr(va).readByteArray(n)));}catch(e){return [];} }
function u8(p){ try{return p.readU8();}catch(e){return 0;} }
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function hex(b){ return b.toString(16).padStart(2,'0'); }

function findFuncStart(va){
    for(let d=0;d<=1024;d++){
        const a=(va-d)>>>0;
        const b0=u8(ptr(a)),b1=u8(ptr(a+1)),b2=u8(ptr(a+2));
        if(b0===0x55&&b1===0x8b&&b2===0xec) return {va:'0x'+a.toString(16), rva:'0x'+(a-W0).toString(16), delta:d};
        if(b0===0x8b&&b1===0xff&&b2===0x55) return {va:'0x'+a.toString(16), rva:'0x'+(a-W0).toString(16), delta:d, hp:true};
    }
    return null;
}

rpc.exports = {
    // 完整反汇编 ctor [0] (256B)
    fullDisasm: function(rvas){
        return rvas.map(function(rva){
            const va = (W0+rva)>>>0;
            return {rva:'0x'+rva.toString(16), bytes: rb(va, 256).map(hex).join(' ')};
        });
    },

    // 找 VoiceRecord 字符串的所有代码引用（支持 LEA + 间接）
    findStrRefs: function(str_rvas){
        const results = [];
        for(const str_rva of str_rvas){
            const str_va = (W0 + str_rva) >>> 0;
            // pattern: 4-byte LE of str_va
            const pat = [str_va&0xff,(str_va>>8)&0xff,(str_va>>16)&0xff,(str_va>>24)&0xff]
                        .map(b=>hex(b)).join(' ');
            let hits; try{hits=Memory.scanSync(wx.base,WXSIZE,pat);}catch(e){continue;}
            for(const h of hits){
                const ref_va = h.address.toUInt32();
                const rref = ref_va - W0;
                if(rref < 0x1000 || rref > 0x25000000) continue;
                const fn = findFuncStart(ref_va);
                if(!fn) continue;
                results.push({
                    str_rva:'0x'+str_rva.toString(16), str_va:'0x'+str_va.toString(16),
                    ref_rva:'0x'+rref.toString(16),
                    func_rva: fn.rva, func_va: fn.va, delta: fn.delta,
                    // 函数前64B
                    fn_bytes: rb(parseInt(fn.va), 64).map(hex).join(' '),
                    // 引用点前后32B
                    ctx_bytes: rb((ref_va-8)>>>0, 32).map(hex).join(' ')
                });
            }
        }
        return results;
    },

    // 在 VoiceRecord 字符串附近扫叫 "sendVoice" 或 "voice" 的函数（找 silk path 写入）
    // 检查 ctor [0] 0x2b738a2 的参数数目（arg count）: 从调用点的 PUSH 数量推断
    findCtorCallers: function(ctor_rva){
        const ctor_va = (W0 + ctor_rva) >>> 0;
        // call rel32 到 ctor_va 的指令
        const delta = ctor_va - (W0 + 0x1000) - 5;
        const d0 = delta&0xff, d1=(delta>>8)&0xff, d2=(delta>>16)&0xff, d3=(delta>>24)&0xff;
        // E8 rel32 pattern
        const pat = 'e8 ' + [d0,d1,d2,d3].map(b=>hex(b)).join(' ');
        let hits; try{hits=Memory.scanSync(wx.base,WXSIZE,pat);}catch(e){return {error:e.message};}
        const results = [];
        for(const h of hits.slice(0,20)){
            const call_va = h.address.toUInt32();
            const call_rva = call_va - W0;
            if(call_rva < 0x1000||call_rva>0x25000000) continue;
            const fn = findFuncStart(call_va);
            if(!fn) continue;
            // 在 call_va 之前 100B 里数 PUSH 指令（近似 arg count）
            const pre = rb((call_va-80)>>>0, 80);
            let push_count = 0;
            for(let i=0;i<pre.length;i++){
                const b=pre[i];
                if(b===0x50||b===0x51||b===0x52||b===0x53||b===0x56||b===0x57) push_count++;
                if(b===0x68||b===0x6a) push_count++; // push imm
                if(b===0xff&&i+1<pre.length&&pre[i+1]===0x75) push_count++; // push [ebp+n]
                if(b===0xff&&i+1<pre.length&&pre[i+1]===0xb5) push_count++; // push [ebp+disp32]
                if(b===0x83&&i+1<pre.length&&pre[i+1]===0xec) break; // sub esp = new stack frame = stop
            }
            results.push({
                call_rva:'0x'+call_rva.toString(16),
                func_rva: fn.rva, delta: fn.delta,
                approx_push_before: push_count,
                pre_bytes: pre.map(hex).join(' ')
            });
        }
        return {ctor_rva:'0x'+ctor_rva.toString(16), callers: results};
    }
};
"""

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

VR_RVAS = [0xab9be6f, 0xac14a50, 0xac14aac, 0xac22c0f, 0xac22c3b]
CTOR_RVAS = [0x2b738a2, 0x2b74832]

def main():
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}
    def on_msg(m,_d):
        if m.get("type")=="send" and m["payload"].get("t")=="ready": ready["v"]=True
        elif m.get("type")=="error": print("[ERR]", m.get("description"))
    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print("[*] full disasm of ctors...")
    full = script.exports_sync.full_disasm(CTOR_RVAS)
    for d in full:
        print(f"\n[func {d['rva']}]")
        b = d["bytes"].split()
        for row in range(0, min(len(b), 96), 16):
            print(f"  +{row:02x}:  {' '.join(b[row:row+16])}")

    print("\n[*] finding VoiceRecord string refs...")
    refs = script.exports_sync.find_str_refs(VR_RVAS)
    print(f"  found {len(refs)} refs")
    seen = {}
    for r in refs:
        fk = r["func_rva"]
        if fk not in seen:
            seen[fk] = r
    for fk, r in list(seen.items())[:10]:
        print(f"\n  [func_rva={r['func_rva']}  str_rva={r['str_rva']}  delta={r['delta']}]")
        b = r["fn_bytes"].split()
        print(f"    fn[0:32]: {' '.join(b[:32])}")
        print(f"    ctx: {r['ctx_bytes'][:80]}")

    print("\n[*] finding ctor callers...")
    callers = script.exports_sync.find_ctor_callers(0x2b738a2)
    print(f"  found {len(callers.get('callers',[]))} callers")
    for c in callers.get("callers", [])[:10]:
        print(f"  call@{c['call_rva']}  in func {c['func_rva']}  ~{c['approx_push_before']} pushes")

    try: script.unload(); session.detach()
    except Exception: pass

    out = OUT_DIR / "voice_ctor_disasm2.json"
    out.write_text(json.dumps({"full":full, "refs":refs, "callers":callers},
                               ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
