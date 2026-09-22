"""
枚举 PostSendMessageTask2 构造器 0x2d338a2 (RVA 0x2b738a2) 的所有 caller。
对每个 CALL 站点，dump 前后各若干字节，用简单模式匹配找 MOV [reg+0x50], imm。
目的：穷举所有 subtype 常量，特别是找出 voice 对应的值。
"""
import sys, time, json, subprocess, re
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent
CTOR_RVAS = [0x2b738a2, 0x2b74832]

JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
const W0 = wx.base.toUInt32();
const CTOR_TARGETS = __CTORS__.map(rva => (W0 + rva) >>> 0);
send({t:'ready', base: '0x'+W0.toString(16), targets: CTOR_TARGETS.map(v=>'0x'+v.toString(16))});

// 读取 .text 段
const modBase = wx.base;
const modEnd  = modBase.add(wx.size);

// 只扫可执行区域
const execRanges = [];
for (const r of Process.enumerateRanges({protection:'r-x', coalesce:false})){
    // 只取属于 wxwork.exe 的段
    if (r.base.compare(modBase) >= 0 && r.base.compare(modEnd) < 0){
        execRanges.push(r);
    }
}
send({t:'ranges', n: execRanges.length});

rpc.exports = {
    hunt: function(){
        const results = [];
        for (const tgt of CTOR_TARGETS){
            const hits = [];
            for (const r of execRanges){
                // 扫 E8 XX XX XX XX 且 XX XX XX XX 是 rel32(current+5 = tgt)
                // 为简化，逐字节扫（.text 通常 ~几十 MB）
                const size = r.size;
                let buf; try { buf = new Uint8Array(r.base.readByteArray(size)); } catch(e){ continue; }
                for (let i = 0; i + 5 <= size; i++){
                    if (buf[i] !== 0xE8) continue;
                    const rel = (buf[i+1] | (buf[i+2]<<8) | (buf[i+3]<<16) | (buf[i+4]<<24));
                    // sign-extend 32-bit rel: JavaScript bitwise is already 32-bit signed
                    const callVA = ((r.base.toUInt32() + i) >>> 0);
                    const target = ((callVA + 5 + rel) >>> 0);
                    if (target === tgt){
                        // dump ±48 bytes context
                        const startOff = Math.max(0, i - 32);
                        const endOff   = Math.min(size, i + 80);
                        const ctxLen   = endOff - startOff;
                        let hex = '';
                        for (let k=startOff; k<endOff; k++){
                            hex += buf[k].toString(16).padStart(2,'0') + ' ';
                        }
                        hits.push({
                            call_va: '0x'+callVA.toString(16),
                            call_rva: '0x'+((callVA - W0) >>> 0).toString(16),
                            ctx_start_va: '0x'+((r.base.toUInt32() + startOff) >>> 0).toString(16),
                            ctx_start_rva: '0x'+((r.base.toUInt32() + startOff - W0) >>> 0).toString(16),
                            ctx_hex: hex.trim(),
                            call_at_offset: i - startOff
                        });
                        if (hits.length >= 200) break;
                    }
                }
                if (hits.length >= 200) break;
            }
            results.push({ctor: '0x'+tgt.toString(16), n_hits: hits.length, hits});
        }
        return results;
    }
};
""".replace("__CTORS__", json.dumps(CTOR_RVAS))

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

# 简单 x86 模式匹配：寻找 MOV [reg+0x50], imm8 / imm32
# c6 47 50 XX          -> mov byte [edi+0x50], XX
# c6 46 50 XX          -> mov byte [esi+0x50], XX
# c6 41 50 XX          -> mov byte [ecx+0x50], XX
# c6 40 50 XX          -> mov byte [eax+0x50], XX
# c6 42 50 XX          -> mov byte [edx+0x50], XX
# c6 43 50 XX          -> mov byte [ebx+0x50], XX
# c6 45 50 XX          -> mov byte [ebp+0x50], XX (uncommon)
# c7 47 50 XX 00 00 00 -> mov dword [edi+0x50], imm32
# c7 87 50 00 00 00 XX XX XX XX -> mov dword [edi+0x50], imm32 (disp32)
# c6 87 50 00 00 00 XX -> mov byte [edi+0x50], XX (disp32 variant)
BYTE_MOV_RE = re.compile(r'\bc6\s+([4][0-7])\s+50\s+([0-9a-f]{2})\b', re.I)
DWORD_MOV_RE = re.compile(r'\bc7\s+([4][0-7])\s+50\s+([0-9a-f]{2})\s+00\s+00\s+00\b', re.I)
BYTE_DISP32_RE  = re.compile(r'\bc6\s+([8][0-7])\s+50\s+00\s+00\s+00\s+([0-9a-f]{2})\b', re.I)
DWORD_DISP32_RE = re.compile(r'\bc7\s+([8][0-7])\s+50\s+00\s+00\s+00\s+([0-9a-f]{2})\s+00\s+00\s+00\b', re.I)

REG_MAP = {
    0x00:'eax',0x01:'ecx',0x02:'edx',0x03:'ebx',
    0x04:'esp',0x05:'ebp',0x06:'esi',0x07:'edi',
}

def scan_subtypes(ctx_hex: str):
    """在 ctx_hex 里找 MOV [reg+0x50], imm"""
    findings = []
    for pat, tag in [(BYTE_MOV_RE, 'byte'),
                      (DWORD_MOV_RE, 'dword'),
                      (BYTE_DISP32_RE, 'byte_disp32'),
                      (DWORD_DISP32_RE, 'dword_disp32')]:
        for m in pat.finditer(ctx_hex):
            modrm = int(m.group(1), 16)
            reg = REG_MAP.get(modrm & 7, '?')
            imm = int(m.group(2), 16)
            findings.append({"kind": tag, "reg": reg, "imm": imm, "match_offset": m.start()})
    return findings

def main():
    pid = get_pid()
    if not pid:
        print("[!] no WXWork"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(JS)
    ready = {"v": False}
    def on_msg(m,_):
        if m.get("type")=="send":
            p = m["payload"]
            if p.get("t")=="ready":
                ready["v"]=True
                print(f"[+] attached PID={pid}  wxbase={p['base']}  targets={p['targets']}")
            elif p.get("t")=="ranges":
                print(f"[+] executable ranges: {p['n']}")
        elif m.get("type")=="error":
            print("[ERR]", m.get("description"))
    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print("[*] hunting callers … (up to a couple minutes)")
    t0 = time.time()
    results = script.exports_sync.hunt()
    dt = time.time() - t0
    print(f"[+] hunt done in {dt:.1f}s")

    for ctor_result in results:
        print(f"\n{'='*70}")
        print(f"ctor {ctor_result['ctor']}: {ctor_result['n_hits']} callers")
        # 汇总所有 subtype 常量
        subtype_stats = {}
        for hit in ctor_result["hits"]:
            findings = scan_subtypes(hit["ctx_hex"])
            hit["subtype_writes"] = findings
            for f in findings:
                subtype_stats[f["imm"]] = subtype_stats.get(f["imm"], 0) + 1

        print(f"  发现的 subtype 常量分布（在 +0x50 附近的 MOV 立即数）：")
        for imm, cnt in sorted(subtype_stats.items()):
            print(f"     subtype = 0x{imm:02x} ({imm:>3})  出现次数 = {cnt}")

        # 前 15 个 caller 详情
        print(f"\n  前 15 个 caller 上下文：")
        for i, hit in enumerate(ctor_result["hits"][:15]):
            sw = hit["subtype_writes"]
            imms = ','.join(f"0x{f['imm']:02x}({f['reg']})" for f in sw) if sw else '-'
            print(f"    [{i:>3}] call@{hit['call_rva']} subtype_writes=[{imms}]")

    out = OUT_DIR / f"ctor_callers_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"pid":pid, "ctor_rvas":[hex(x) for x in CTOR_RVAS], "results":results},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out.name}")

    try: script.unload(); session.detach()
    except Exception: pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
