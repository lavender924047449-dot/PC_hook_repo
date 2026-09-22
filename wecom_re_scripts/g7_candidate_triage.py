import pefile
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000

CAND_RVAS = [
    0x57C9417,  # pc_send_voice_text xref
    0x04928D,   # kSendVoiceAsrKey xref
    0x0F1FFAA,  # voice2text_auto_polish_chat xref
    0x0F22504,  # CMD_AI_RECORD_UPDATE_OFFLINE xref
    0x81E49CF,  # aes_key table path
    0x81E6769,  # aes_key table path
    0x83C5BFB,  # aes_key table path
    0x1CC12E,   # imm 0x602
]


def find_text(pe):
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            return s
    raise RuntimeError(".text not found")


def find_func_start(text_va, td, va, max_back=0x800):
    off = va - text_va
    if off < 0 or off >= len(td):
        return None
    start = max(0, off - max_back)
    for i in range(off, start, -1):
        if td[i : i + 3] == b"\x55\x8b\xec":
            prev = td[i - 1] if i > 0 else 0xCC
            if prev in (0xCC, 0xC3, 0xC2, 0x90):
                return text_va + i
    return None


def dump_disasm(md, td, base, n=90):
    out = []
    for idx, ins in enumerate(md.disasm(td, base)):
        out.append((ins.address, ins.mnemonic, ins.op_str, ins.bytes.hex()))
        if idx + 1 >= n:
            break
        if ins.mnemonic.startswith("ret") and idx > 8:
            break
    return out


def main():
    pe = pefile.PE(PE_PATH, fast_load=True)
    text = find_text(pe)
    text_va = IB + text.VirtualAddress
    td = text.get_data()
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    for rva in CAND_RVAS:
        va = IB + rva
        print("\n" + "=" * 90)
        print(f"candidate RVA=0x{rva:x} VA=0x{va:08x}")
        fs = find_func_start(text_va, td, va)
        if fs is None:
            print("  [!] function start not found by prologue scan")
            continue
        print(f"  func_start RVA=0x{fs-IB:x} VA=0x{fs:08x}")
        off = fs - text_va
        blob = td[off : off + 0x240]
        insns = dump_disasm(md, blob, fs, n=80)
        for a, m, o, raw in insns:
            mark = ">>" if a == va else "  "
            print(f"{mark} 0x{a:08x} rva=0x{a-IB:x}  {m:<7s} {o:<40s} ; {raw}")


if __name__ == "__main__":
    main()
