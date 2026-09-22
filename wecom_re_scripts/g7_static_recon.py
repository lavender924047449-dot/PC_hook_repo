import pefile
import re
import struct
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000

KEYWORDS_ASCII = [
    b"voice_time",
    b"cdn_key",
    b"aes_key",
    b"syncKey",
    b"SILK",
    b"silk",
    b"voice",
    b"Voice",
    b"SendVoice",
    b"send_voice",
    b"0602",
    b"cmd_0x0602",
    b"ITEM_VOICE",
]

DER_PREFIX = bytes.fromhex("308189020102")


def iter_sections(pe):
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        va = IB + s.VirtualAddress
        data = s.get_data()
        yield name, va, data


def va_to_rva(va):
    return va - IB


def find_all(data, pat):
    out = []
    pos = 0
    while True:
        i = data.find(pat, pos)
        if i < 0:
            return out
        out.append(i)
        pos = i + 1


def scan_keyword_hits(pe):
    hits = []
    for sec_name, base_va, data in iter_sections(pe):
        for kw in KEYWORDS_ASCII:
            for off in find_all(data, kw):
                va = base_va + off
                hits.append((kw.decode("ascii", errors="replace"), sec_name, va))
    return hits


def scan_der_hits(pe):
    hits = []
    for sec_name, base_va, data in iter_sections(pe):
        for off in find_all(data, DER_PREFIX):
            va = base_va + off
            hits.append((sec_name, va))
    return hits


def find_imm_xrefs(pe, target_va):
    needle = struct.pack("<I", target_va & 0xFFFFFFFF)
    refs = []
    text = pe.sections[0]
    # locate .text accurately
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            text = s
            break
    text_va = IB + text.VirtualAddress
    td = text.get_data()
    for off in find_all(td, needle):
        refs.append(text_va + off)
    return refs


def scan_cmp_602_in_text(pe):
    text = None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            text = s
            break
    if text is None:
        return []
    base = IB + text.VirtualAddress
    td = text.get_data()
    out = []
    # 81 /7 id (cmp r/m32, imm32) and 3d id (cmp eax, imm32), imm = 0x602
    for i in range(0, len(td) - 6):
        b0 = td[i]
        if b0 == 0x3D:
            imm = struct.unpack_from("<I", td, i + 1)[0]
            if imm == 0x602:
                out.append((base + i, td[i : i + 5].hex()))
        elif b0 == 0x81:
            modrm = td[i + 1]
            if ((modrm >> 3) & 0x7) == 7:
                imm = struct.unpack_from("<I", td, i + 2)[0]
                if imm == 0x602:
                    out.append((base + i, td[i : i + 6].hex()))
    return out


def main():
    pe = pefile.PE(PE_PATH, fast_load=True)

    print("=== G7-α: keyword hits ===")
    kw_hits = scan_keyword_hits(pe)
    print(f"keyword hit count: {len(kw_hits)}")
    kw_by_name = defaultdict(list)
    for kw, sec, va in kw_hits:
        kw_by_name[kw].append((sec, va))
    for kw in sorted(kw_by_name):
        rows = kw_by_name[kw]
        print(f"\n[{kw}] hits={len(rows)}")
        for sec, va in rows[:8]:
            print(f"  {sec:8s} VA=0x{va:08x} RVA=0x{va_to_rva(va):x}")
        if len(rows) > 8:
            print("  ...")

    # xref top anchors: cdn_key / aes_key / voice_time / ITEM_VOICE
    anchors = [b"cdn_key", b"aes_key", b"voice_time", b"ITEM_VOICE", b"SendVoice", b"send_voice"]
    print("\n=== G7-α: immediate xrefs in .text (top anchors) ===")
    for a in anchors:
        name = a.decode("ascii", errors="replace")
        vas = []
        for sec_name, base_va, data in iter_sections(pe):
            for off in find_all(data, a):
                vas.append(base_va + off)
        if not vas:
            print(f"[{name}] no literal hit")
            continue
        print(f"[{name}] literals={len(vas)}")
        for va in vas[:4]:
            refs = find_imm_xrefs(pe, va)
            print(f"  lit VA=0x{va:08x} refs={len(refs)}")
            for r in refs[:12]:
                print(f"    xref @ RVA 0x{va_to_rva(r):x}")
            if len(refs) > 12:
                print("    ...")

    print("\n=== G7-β: cmp imm32 == 0x602 in .text ===")
    cmp_hits = scan_cmp_602_in_text(pe)
    print(f"cmp-0x602 hits: {len(cmp_hits)}")
    for va, raw in cmp_hits[:120]:
        print(f"  VA=0x{va:08x} RVA=0x{va_to_rva(va):x} raw={raw}")
    if len(cmp_hits) > 120:
        print("  ...")

    print("\n=== G7-γ: DER prefix 30 81 89 02 01 02 ===")
    der_hits = scan_der_hits(pe)
    print(f"DER hits: {len(der_hits)}")
    for sec, va in der_hits[:40]:
        print(f"  {sec:8s} VA=0x{va:08x} RVA=0x{va_to_rva(va):x}")
        refs = find_imm_xrefs(pe, va)
        print(f"    xrefs in .text: {len(refs)}")
        for r in refs[:10]:
            print(f"      RVA 0x{va_to_rva(r):x}")
        if len(refs) > 10:
            print("      ...")
    if len(der_hits) > 40:
        print("  ...")


if __name__ == "__main__":
    main()
