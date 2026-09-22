"""换一批关键字，在整个 exe 里搜字符串常量 + 找它们在 .text 的引用点。

新一批关键字（避免和 §47.16.14 重复）：
- 1538 / "1538" / VoiceCmd / VoiceContent / VoiceMessage / VoiceItem
- VItem / V_Item / VItemContent
- LongLinkCmd / LongLinkSend / LongLinkPack
- SendVoiceMsg / SendVoiceMessage / MMSendVoice
- mediasilk / MediaSilk / MediaVoice / VoiceMedia
- cdn_voice / voice_upload / VoiceUploader
- audio_ / Audio  (widen)
- speak / Speak / talk
- silkv3 / SilkV3 / silk_v3

策略：
1) 对每个 .rdata 段的 C 字符串扫一遍
2) 对匹配到的字符串 VA，扫全 .text 找 `push imm=VA` / `mov reg, VA` / `push offset [VA]` (imm ref)
3) 对每个引用点做函数起点回溯 + 简单反汇编（前 100 条 insn 抽字符串）

同时输出：全 exe 里包含 "voice" 或 "Voice" 或 "silk" 或 "SILK" 的所有 C 字符串（限 800 条），便于人肉浏览。
"""
import pefile
import re
import sys
from collections import defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE_PATH = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000

NEW_KWS = [
    "1538", "VoiceCmd", "VoiceContent", "VoiceMessage", "VoiceItem",
    "VItem", "V_Item", "VItemContent",
    "LongLinkCmd", "LongLinkSend", "LongLinkPack", "LongLink",
    "SendVoiceMsg", "SendVoiceMessage", "MMSendVoice", "MMVoice",
    "mediasilk", "MediaSilk", "MediaVoice", "VoiceMedia",
    "cdn_voice", "voice_upload", "VoiceUploader",
    "SilkV3", "silk_v3", "SILKV3",
    "voice_len", "voice_data", "voice_buffer",
    "ItemVoice", "kVoice", "kSILK", "kSilk",
]

BROWSE_SUBSTRS = ["voice", "Voice", "silk", "SILK", "Silk"]


def load_sections(pe):
    return [
        (s.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
         IB + s.VirtualAddress,
         IB + s.VirtualAddress + len(s.get_data()),
         s.get_data())
        for s in pe.sections
    ]


def scan_cstrings(secs, minlen=4, maxlen=200):
    """Yield (va, s) for all printable C strings in .rdata / .data."""
    out = []
    for name, s, e, data in secs:
        if name not in (".rdata", ".data", "_RDATA"):
            continue
        i = 0
        while i < len(data):
            end = data.find(b"\x00", i)
            if end < 0: break
            if end - i >= minlen and end - i <= maxlen:
                buf = data[i:end]
                try:
                    txt = buf.decode("ascii")
                    if all(0x20 <= b < 0x7F or b in (9, 10, 13) for b in buf):
                        out.append((s + i, txt))
                except UnicodeDecodeError:
                    pass
            i = end + 1
    return out


def find_immref_in_text(text_data, text_va, target_va):
    """Find all `push/mov ... imm=target_va` in .text. Return list of VAs of the instruction start."""
    imm = target_va.to_bytes(4, "little")
    hits = []
    # push imm32: 68 XX XX XX XX
    for m in re.finditer(re.escape(b"\x68" + imm), text_data):
        hits.append(("push", text_va + m.start()))
    # mov r32, imm32: B8..BF XX XX XX XX
    for pfx in range(0xB8, 0xC0):
        for m in re.finditer(re.escape(bytes([pfx]) + imm), text_data):
            hits.append(("mov r32", text_va + m.start()))
    # mov [ebp+X], imm32: C7 45 XX XX XX XX XX
    for m in re.finditer(rb"\xC7\x45." + re.escape(imm), text_data):
        hits.append(("mov [ebp+X]", text_va + m.start()))
    return hits


def read_at(secs, va, n):
    for name, s, e, data in secs:
        if s <= va < e:
            return data[va - s : va - s + n]
    return b""


def is_str_at(secs, va, minlen=4, maxlen=200):
    data = read_at(secs, va, maxlen)
    if not data: return None
    end = data.find(b"\x00")
    if end < minlen: return None
    s = data[:end]
    try: s.decode("ascii")
    except UnicodeDecodeError: return None
    if not all(0x20 <= b < 0x7F or b in (9,10,13) for b in s): return None
    return s.decode("ascii")


def main():
    pe = pefile.PE(PE_PATH, fast_load=True)
    secs = load_sections(pe)
    text_name, text_va, text_end, text_data = next(x for x in secs if x[0] == ".text")

    print("[*] scanning C-strings in .rdata/.data/_RDATA...")
    all_strs = scan_cstrings(secs)
    print(f"[+] total strings: {len(all_strs)}")

    # 1) 新关键字精准匹配
    print("\n" + "=" * 90)
    print(f"[SECTION 1] NEW-KEYWORD exact matches in strings")
    print("=" * 90)
    for kw in NEW_KWS:
        matches = [(va, s) for va, s in all_strs if kw in s]
        if not matches: continue
        print(f"\n★ kw='{kw}' ({len(matches)} strings):")
        for va, s in matches[:30]:
            print(f"    @0x{va:08x}  \"{s[:120]}\"")

    # 2) 浏览子串（voice/Voice/silk/SILK/Silk）
    print("\n" + "=" * 90)
    print(f"[SECTION 2] BROWSE substrings (voice/Voice/silk/SILK/Silk)")
    print("=" * 90)
    browse_hits = []
    for va, s in all_strs:
        if any(k in s for k in BROWSE_SUBSTRS):
            browse_hits.append((va, s))
    print(f"[+] total: {len(browse_hits)} strings")
    # print first 200
    for va, s in browse_hits[:200]:
        print(f"  @0x{va:08x}  \"{s[:140]}\"")
    if len(browse_hits) > 200:
        print(f"  ... ({len(browse_hits) - 200} more)")

    # 3) 对高价值命中做 xref
    print("\n" + "=" * 90)
    print(f"[SECTION 3] Code XREFs for high-value keyword hits")
    print("=" * 90)
    hi_val_kw = ["VoiceCmd", "VoiceContent", "VoiceMessage", "VoiceItem", "VItem",
                 "SendVoiceMsg", "SendVoiceMessage", "MMSendVoice",
                 "MediaSilk", "MediaVoice", "VoiceUploader",
                 "SilkV3", "silk_v3", "voice_len", "voice_data",
                 "LongLinkCmd", "kVoice"]
    for kw in hi_val_kw:
        for va, s in all_strs:
            if kw in s:
                refs = find_immref_in_text(text_data, text_va, va)
                if refs:
                    print(f"\n★ '{s[:80]}'  @0x{va:08x}  ({len(refs)} xrefs)")
                    for kind, at_va in refs[:6]:
                        print(f"    {kind:<12} @wx+0x{at_va-IB:08x}")


if __name__ == "__main__":
    main()
