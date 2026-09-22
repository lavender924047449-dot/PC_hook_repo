# hunt_voice_ctor.py — 找 PostSendMessageTask2 voice 构造入口
#
# 策略（纯只读，不用 Interceptor）：
#   1. 找 W0+0xABBB210（vtable VA）在 wxwork.exe .text 段的所有引用（MOV/PUSH 立即数）
#   2. 每个引用点向上最多 512B 找函数 prologue（55 8B EC / 8B FF 55 等）
#   3. 对每个候选函数前 128B 反汇编，分析参数个数 / 调用约定
#   4. 进一步过滤：函数内含 voice 特有字段写入（subtype=2, +0x50, +0x1b8）
#
# 用法：python hunt_voice_ctor.py [--pid N]
from __future__ import annotations
import argparse, json, subprocess, sys, time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent
VOICE_VTABLE_RVA = 0xABBB210  # PostSendMessageTask2 vtable RVA

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
if (!wx) throw new Error('wxwork.exe not found');
const W0 = wx.base.toUInt32();
const WXSIZE = wx.size;
send({t:'info', base:'0x'+W0.toString(16), size:'0x'+WXSIZE.toString(16)});

const VTABLE_RVA = __VTABLE_RVA__;
const VTABLE_VA  = (W0 + VTABLE_RVA) >>> 0;

function u8(p){  try{return p.readU8();}  catch(e){return 0;} }
function u32(p){ try{return p.readU32();} catch(e){return 0;} }

function readBytes(addr, n){
    try{ return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e){ return []; }
}

// pattern: 4-byte little-endian VTABLE_VA in wxwork.exe code
function vtablePattern(){
    const v = VTABLE_VA;
    return [(v&0xff),(v>>8&0xff),(v>>16&0xff),(v>>24&0xff)]
        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
}

// Walk backward from ref_addr to find function prologue (up to 512B)
// MSVC prologues:  55 8B EC  (PUSH EBP; MOV EBP,ESP)
//                  8B FF 55  (MOV EDI,EDI; PUSH EBP)  [hotpatch]
//                  55        (PUSH EBP only)
function findFuncStart(ref_addr){
    for (let delta = 0; delta <= 512; delta++){
        const a = (ref_addr - delta) >>> 0;
        const b0 = u8(ptr(a));
        const b1 = u8(ptr(a+1));
        const b2 = u8(ptr(a+2));
        // 55 8B EC
        if (b0 === 0x55 && b1 === 0x8b && b2 === 0xec) return {va:'0x'+a.toString(16), rva:'0x'+(a-W0).toString(16), prologue:'55_8b_ec', delta};
        // 8B FF 55 8B EC  (hot-patch)
        if (b0 === 0x8b && b1 === 0xff && b2 === 0x55) return {va:'0x'+a.toString(16), rva:'0x'+(a-W0).toString(16), prologue:'8bff_hotpatch', delta};
    }
    return null;
}

// Disassemble first 128B: look for sub esp,N and push/call patterns
function quickDisasm(func_va){
    const bytes = readBytes(func_va, 256);
    if (!bytes.length) return {bytes_hex:'', sub_esp:null, frame_size:null};
    const h = bytes.map(b=>b.toString(16).padStart(2,'0')).join(' ');
    let frame_size = null;
    for (let i=0;i<bytes.length-2;i++){
        // 83 EC nn  (sub esp, nn)
        if (bytes[i]===0x83 && bytes[i+1]===0xec){ frame_size=bytes[i+2]; break; }
        // 81 EC nn nn nn nn  (sub esp, nnnnnnnn)
        if (bytes[i]===0x81 && bytes[i+1]===0xec && i+5<bytes.length){
            frame_size=(bytes[i+2])|(bytes[i+3]<<8)|(bytes[i+4]<<16)|(bytes[i+5]<<24); break;
        }
    }
    return {bytes_hex: h.slice(0,256), frame_size};
}

rpc.exports = {
    huntCtors: function(){
        const pat = vtablePattern();
        send({t:'info', msg:'scanning for vtable pattern: '+pat+' (VA=0x'+VTABLE_VA.toString(16)+')'});
        let hits;
        try { hits = Memory.scanSync(wx.base, WXSIZE, pat); }
        catch(e){ return {error: e.message}; }
        send({t:'info', msg:'vtable refs in code: '+hits.length});

        const results = [];
        for (const h of hits){
            const ref_va = h.address.toUInt32();
            const ref_rva = ref_va - W0;
            // 跳过 .rdata / vtable 本身（RVA < 0x3000000 code region heuristic）
            // code section heuristic: RVA 0x1000 ~ 0x25000000 (wxwork.exe is ~270MB)
            if (ref_rva < 0x1000 || ref_rva > 0x25000000) continue;

            // check preceding byte for MOV/PUSH context
            const prev = u8(ptr(ref_va - 1));
            const is_push = (prev === 0x68);          // PUSH imm32
            const is_mov  = (prev === 0x00 || prev === 0x05 || prev === 0x01); // mov [ecx] / [eax]
            const b_m2    = u8(ptr(ref_va - 2));
            const is_mov2 = (b_m2 === 0xC7);          // C7 0x xx xx xx xx

            const func = findFuncStart(ref_va);
            if (!func) continue;

            const dis = quickDisasm(parseInt(func.va));
            results.push({
                ref_va: '0x'+ref_va.toString(16),
                ref_rva: '0x'+ref_rva.toString(16),
                prev_byte: '0x'+prev.toString(16),
                context: is_push ? 'PUSH' : (is_mov2 ? 'MOV_C7' : 'OTHER'),
                func_va: func.va,
                func_rva: func.rva,
                prologue: func.prologue,
                delta_from_ref: func.delta,
                frame_size: dis.frame_size,
                bytes_hex: dis.bytes_hex,
            });
        }
        return {pattern: pat, raw_hits: hits.length, ctors: results};
    },

    // 额外：扫 wxwork.exe 代码里含 "voice" / ".silk" 字符串引用的函数
    huntVoiceStrRefs: function(){
        const patterns = [
            {name:'voice', pat:'76 6f 69 63 65'},   // "voice"
            {name:'silk',  pat:'2e 73 69 6c 6b'},   // ".silk"
            {name:'VoiceRecord', pat:'56 6f 69 63 65 52 65 63 6f 72 64'}, // "VoiceRecord"
        ];
        const out = {};
        for (const {name, pat} of patterns){
            let str_hits;
            try{ str_hits = Memory.scanSync(wx.base, WXSIZE, pat); }
            catch(e){ out[name]={error:e.message}; continue; }
            const locs = str_hits.slice(0,30).map(h=>({
                rva: '0x'+((h.address.toUInt32()-W0)>>>0).toString(16),
                ctx: Array.from(new Uint8Array(h.address.readByteArray(Math.min(h.size+32,64))))
                         .map(b=>b.toString(16).padStart(2,'0')).join(' ')
            }));
            out[name] = {count: str_hits.length, locs};
        }
        return out;
    }
};
send({t:'ready'});
""".replace("__VTABLE_RVA__", hex(VOICE_VTABLE_RVA))


def get_pid():
    r = subprocess.run(["powershell", "-Command",
        "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int)
    args = ap.parse_args()

    pid = args.pid or get_pid()
    if not pid:
        print("[!] WXWork not running"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}

    def on_msg(m, _d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "ready": ready["v"] = True
            elif p.get("t") == "info": print(f"  [js] {p.get('msg', p)}")
        elif m.get("type") == "error":
            print(f"  [ERR] {m.get('description')}")

    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print(f"[*] PID={pid}  hunting PostSendMessageTask2 constructors...")
    result = script.exports_sync.hunt_ctors()
    print(f"[*] raw vtable refs: {result.get('raw_hits',0)}  candidate ctors: {len(result.get('ctors',[]))}")

    print("\n[*] hunting voice/silk string refs...")
    str_refs = script.exports_sync.hunt_voice_str_refs()
    for k, v in str_refs.items():
        print(f"  '{k}': {v.get('count', 'err')} hits")

    try: script.unload(); session.detach()
    except Exception: pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"voice_ctor_hunt_{ts}.json"
    out.write_text(json.dumps({
        "pid": pid, "vtable_rva": hex(VOICE_VTABLE_RVA),
        "ctors": result, "str_refs": str_refs
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out.name}")

    # 打印候选构造函数
    ctors = result.get("ctors", [])
    if ctors:
        print(f"\n=== 候选构造函数（共 {len(ctors)} 个）===")
        for i, c in enumerate(ctors[:20]):
            print(f"  [{i}] func_rva={c['func_rva']}  context={c['context']}"
                  f"  delta={c['delta_from_ref']}  frame={c.get('frame_size')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
