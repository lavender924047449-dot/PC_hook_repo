"""
分析 hook_callers JSON 里两个 caller 的前后上下文，
扩大扫描范围到 ±200B，并打印完整反汇（简单字节序列分析）。
"""
import json, re, struct
from pathlib import Path

OUT = Path(__file__).resolve().parent

def find_latest(prefix):
    files = sorted(OUT.glob(f"{prefix}*.json"), key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None

f = find_latest("hook_callers_")
if not f: print("no hook_callers_*.json"); exit(1)
data = json.loads(f.read_text())
print(f"file: {f.name}")

def hex_decode_insn(h: str, limit=60):
    """极简 x86 单字节/模式解读，只打印关键指令"""
    bytes_ = bytes.fromhex(h.replace(' ',''))
    out = []
    i = 0
    while i < len(bytes_) and len(out) < limit:
        b = bytes_[i]
        # jump short
        if b == 0xEB:
            rel = struct.unpack_from("b", bytes_, i+1)[0]
            out.append(f"+{i:03x}: JMP SHORT +{rel+2} (→+{i+rel+2:03x})")
            i += 2
        # jz / jnz short
        elif b in (0x74,0x75):
            rel = struct.unpack_from("b", bytes_, i+1)[0]
            mn = "JZ" if b==0x74 else "JNZ"
            out.append(f"+{i:03x}: {mn} SHORT +{rel+2} (→+{i+rel+2:03x})")
            i += 2
        # jz/jnz long
        elif b == 0x0F and i+1 < len(bytes_) and bytes_[i+1] in (0x84,0x85):
            rel = struct.unpack_from("<i", bytes_, i+2)[0]
            mn = "JZ" if bytes_[i+1]==0x84 else "JNZ"
            out.append(f"+{i:03x}: {mn} LONG (→+{i+rel+6:03x})")
            i += 6
        # CALL rel32
        elif b == 0xE8:
            rel = struct.unpack_from("<i", bytes_, i+1)[0]
            out.append(f"+{i:03x}: CALL →(+{i+rel+5:03x} rel)")
            i += 5
        # MOV [reg+off8], imm8   c6 4X YY ZZ
        elif b == 0xC6 and i+3 < len(bytes_) and (bytes_[i+1] & 0xF8) == 0x40:
            off8 = bytes_[i+2]; imm = bytes_[i+3]
            rm = bytes_[i+1] & 7
            rn = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][rm]
            out.append(f"+{i:03x}: MOV byte [{rn}+0x{off8:02x}], 0x{imm:02x}  ← {'<<<subtype write!>>>' if off8==0x50 else ''}")
            i += 4
        # MOV [reg+off8], imm32  c7 4X YY ZZ ZZ ZZ ZZ
        elif b == 0xC7 and i+6 < len(bytes_) and (bytes_[i+1] & 0xF8) == 0x40:
            off8 = bytes_[i+2]
            imm = struct.unpack_from("<I", bytes_, i+3)[0]
            rm = bytes_[i+1] & 7
            rn = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][rm]
            out.append(f"+{i:03x}: MOV dword [{rn}+0x{off8:02x}], 0x{imm:08x}  ← {'<<<subtype write!>>>' if off8==0x50 else ''}")
            i += 7
        # MOV reg, [reg+off8]    8b 4X YY
        elif b == 0x8B and i+2 < len(bytes_) and (bytes_[i+1] & 0xF8) == 0x40:
            off8 = bytes_[i+2]
            r_dst = (bytes_[i+1] >> 3) & 7
            r_src = bytes_[i+1] & 7
            dn = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][r_dst]
            sn = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][r_src]
            out.append(f"+{i:03x}: MOV {dn}, [{sn}+0x{off8:02x}]")
            i += 3
        # PUSH imm8
        elif b == 0x6A:
            imm = bytes_[i+1]
            out.append(f"+{i:03x}: PUSH imm8 0x{imm:02x} ({imm})")
            i += 2
        # PUSH imm32
        elif b == 0x68:
            imm = struct.unpack_from("<I", bytes_, i+1)[0]
            out.append(f"+{i:03x}: PUSH imm32 0x{imm:08x}")
            i += 5
        # LEA reg, [reg+off8]  8d 4X YY
        elif b == 0x8D and i+2 < len(bytes_) and (bytes_[i+1] & 0xF8) == 0x40:
            off8 = bytes_[i+2]
            r_dst = (bytes_[i+1] >> 3) & 7
            r_src = bytes_[i+1] & 7
            dn = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][r_dst]
            sn = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][r_src]
            out.append(f"+{i:03x}: LEA {dn}, [{sn}+0x{off8:02x}]")
            i += 3
        # RET
        elif b in (0xC2, 0xC3):
            out.append(f"+{i:03x}: RET"); i += (3 if b==0xC2 else 1)
        else:
            out.append(f"+{i:03x}: {b:02x} ...")
            i += 1
    return out

for caller_rva, info in data["hits"].items():
    print(f"\n{'='*70}")
    print(f"caller RVA {caller_rva}  ctor={info['ctor_rva']}  call_count={info['count']}")

    before = info.get("ctx_before_call","")
    after  = info.get("ctx_after_call","")

    print("\n--- BEFORE call (up to -32B from return addr) ---")
    for ln in hex_decode_insn(before, 30): print(f"  {ln}")

    print("\n--- AFTER call (up to +80B after return addr) ---")
    for ln in hex_decode_insn(after, 60): print(f"  {ln}")
