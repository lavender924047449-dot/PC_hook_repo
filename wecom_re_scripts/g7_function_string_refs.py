import pefile
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000

FUNC_START_RVAS = [
    0x57C9062,
    0x81E47F2,
    0x81E6673,
    0x83C57E2,
    0xF1F9A0,
]


def find_text(pe):
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            return s
    raise RuntimeError("no .text")


def read_va(pe, va, n):
    for s in pe.sections:
        base = IB + s.VirtualAddress
        end = base + s.Misc_VirtualSize
        if base <= va < end:
            data = s.get_data()
            off = va - base
            return data[off : min(off + n, len(data))]
    return b""


def read_cstr(pe, va, maxn=180):
    b = read_va(pe, va, maxn)
    if not b:
        return None
    z = b.find(b"\x00")
    if z < 0:
        z = len(b)
    try:
        s = b[:z].decode("utf-8")
    except Exception:
        try:
            s = b[:z].decode("latin1")
        except Exception:
            return None
    if len(s.strip()) < 2:
        return None
    return s


def main():
    pe = pefile.PE(PE_PATH, fast_load=True)
    text = find_text(pe)
    base = IB + text.VirtualAddress
    td = text.get_data()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    for rva in FUNC_START_RVAS:
        va = IB + rva
        print("\n" + "=" * 88)
        print(f"func RVA=0x{rva:x} VA=0x{va:08x}")
        code = read_va(pe, va, 0x500)
        str_refs = []
        for ins in md.disasm(code, va):
            if ins.mnemonic.startswith("ret"):
                break
            for op in ins.operands:
                if op.type == 2:  # IMM
                    imm = op.imm & 0xFFFFFFFF
                    # likely global VA in high range
                    if 0x0A000000 <= imm <= 0x10000000:
                        s = read_cstr(pe, imm)
                        if s:
                            str_refs.append((ins.address, imm, s))
        seen = set()
        for a, imm, s in str_refs:
            key = (imm, s)
            if key in seen:
                continue
            seen.add(key)
            print(f"  insn RVA=0x{a-IB:x} -> str RVA=0x{imm-IB:x}  {s[:140]!r}")


if __name__ == "__main__":
    main()
