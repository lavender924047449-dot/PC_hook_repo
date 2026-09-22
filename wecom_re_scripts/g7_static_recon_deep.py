import pefile
import struct
import sys
from collections import defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_IMM

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000

TARGETS = [b"SendVoice", b"send_voice", b"voice_time", b"aes_key", b"ITEM_VOICE", b"syncKey"]


def find_all(data, pat):
    pos = 0
    out = []
    while True:
        i = data.find(pat, pos)
        if i < 0:
            return out
        out.append(i)
        pos = i + 1


def iter_sections(pe):
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        va = IB + s.VirtualAddress
        data = s.get_data()
        yield s, name, va, data


def va_to_rva(va):
    return va - IB


def read_func_window(text_va, text_data, ref_va, before=64, after=96):
    off = ref_va - text_va
    if off < 0 or off >= len(text_data):
        return b""
    b = max(0, off - before)
    e = min(len(text_data), off + after)
    return text_data[b:e]


def disasm_with_imm_602(pe):
    text = None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            text = s
            break
    if text is None:
        return []
    base = IB + text.VirtualAddress
    data = text.get_data()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    hits = []
    for ins in md.disasm(data, base):
        for op in ins.operands:
            if op.type == X86_OP_IMM and (op.imm & 0xFFFFFFFF) == 0x602:
                hits.append(ins)
                break
    return hits


def main():
    pe = pefile.PE(PE_PATH, fast_load=True)

    # collect string VAs
    str_hits = defaultdict(list)
    for _s, sec_name, base_va, data in iter_sections(pe):
        for t in TARGETS:
            for off in find_all(data, t):
                str_hits[t].append((sec_name, base_va + off))

    print("=== G7 deep: target strings ===")
    for t in TARGETS:
        rows = str_hits[t]
        print(f"\n[{t.decode()}] hits={len(rows)}")
        for sec, va in rows[:20]:
            print(f"  {sec:8s} VA=0x{va:08x} RVA=0x{va_to_rva(va):x}")

    # global 4-byte references to string literal VAs
    sec_cache = list(iter_sections(pe))
    refs_by_target = {}
    for t in TARGETS:
        refs = []
        for sec, sec_name, base_va, data in sec_cache:
            for _sname, lit_va in str_hits[t]:
                needle = struct.pack("<I", lit_va & 0xFFFFFFFF)
                for off in find_all(data, needle):
                    refs.append((sec_name, base_va + off, lit_va))
        refs_by_target[t] = refs

    print("\n=== G7 deep: global pointer refs (any section) ===")
    for t in TARGETS:
        print(f"\n[{t.decode()}] refs={len(refs_by_target[t])}")
        for sec, va, lit in refs_by_target[t][:40]:
            print(
                f"  ref@{sec:8s} VA=0x{va:08x} RVA=0x{va_to_rva(va):x} -> lit RVA=0x{va_to_rva(lit):x}"
            )
        if len(refs_by_target[t]) > 40:
            print("  ...")

    # second hop: refs-to-refs from .text (string table indirection)
    text = None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            text = s
            break
    text_va = IB + text.VirtualAddress
    text_data = text.get_data()

    print("\n=== G7 deep: second-hop .text refs (ptr-table -> code) ===")
    code_hits = defaultdict(list)
    for t in TARGETS:
        seen = set()
        for sec, ref_va, lit_va in refs_by_target[t]:
            needle = struct.pack("<I", ref_va & 0xFFFFFFFF)
            for off in find_all(text_data, needle):
                xva = text_va + off
                if xva in seen:
                    continue
                seen.add(xva)
                code_hits[t].append((xva, ref_va, lit_va))

        print(f"\n[{t.decode()}] code second-hop hits={len(code_hits[t])}")
        for xva, ref_va, lit_va in code_hits[t][:80]:
            win = read_func_window(text_va, text_data, xva, before=10, after=14)
            print(
                f"  code RVA=0x{va_to_rva(xva):x} via ref RVA=0x{va_to_rva(ref_va):x} lit RVA=0x{va_to_rva(lit_va):x} raw={win.hex()}"
            )
        if len(code_hits[t]) > 80:
            print("  ...")

    # capstone immediate 0x602 scan
    print("\n=== G7 deep: capstone imm == 0x602 ===")
    imm_hits = disasm_with_imm_602(pe)
    print(f"imm-0x602 instructions: {len(imm_hits)}")
    for ins in imm_hits[:200]:
        print(f"  0x{ins.address:08x} rva=0x{va_to_rva(ins.address):x}  {ins.mnemonic} {ins.op_str}")
    if len(imm_hits) > 200:
        print("  ...")

    # summary
    print("\n=== candidate RVAs (union of second-hop code hits) ===")
    cand = set()
    for t in TARGETS:
        for xva, _r, _l in code_hits[t]:
            cand.add(va_to_rva(xva))
    for rva in sorted(cand):
        print(f"  0x{rva:x}")


if __name__ == "__main__":
    main()
