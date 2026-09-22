import pefile
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000

TARGETS = [
    b"pc_send_voice_text",
    b"kSendVoiceAsrKey",
    b"voice2text_auto_polish_chat",
    b"total_voice_time",
    b"file_id:",
    b"CreateOrUpdateOfflineStreamVoice",
    b"CMD_AI_RECORD_UPDATE_OFFLINE",
]


def find_all(data, pat):
    out = []
    pos = 0
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


def disasm_around(text_va, text_data, ref_va, window=32):
    off = ref_va - text_va
    b = max(0, off - window)
    e = min(len(text_data), off + window)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    lines = []
    for ins in md.disasm(text_data[b:e], text_va + b):
        mark = ">>" if ins.address == ref_va else "  "
        lines.append(f"{mark} 0x{ins.address:08x} rva=0x{va_to_rva(ins.address):x}  {ins.mnemonic} {ins.op_str}")
    return lines


def main():
    pe = pefile.PE(PE_PATH, fast_load=True)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    text_va = IB + text.VirtualAddress
    text_data = text.get_data()

    for t in TARGETS:
        print(f"\n=== target {t.decode(errors='replace')} ===")
        lit_vas = []
        for _s, sec_name, base_va, data in iter_sections(pe):
            for off in find_all(data, t):
                va = base_va + off
                lit_vas.append((sec_name, va))
        print(f"literal hits={len(lit_vas)}")
        for sec, va in lit_vas[:10]:
            print(f"  lit {sec} VA=0x{va:08x} RVA=0x{va_to_rva(va):x}")

        for sec, va in lit_vas[:5]:
            needle = struct.pack("<I", va & 0xFFFFFFFF)
            refs = []
            for off in find_all(text_data, needle):
                refs.append(text_va + off)
            print(f"  -> direct .text refs={len(refs)} for lit RVA=0x{va_to_rva(va):x}")
            for r in refs[:8]:
                print(f"     xref RVA=0x{va_to_rva(r):x}")
            if refs:
                print("     disasm:")
                for line in disasm_around(text_va, text_data, refs[0], window=20)[:12]:
                    print("     " + line)


if __name__ == "__main__":
    main()
