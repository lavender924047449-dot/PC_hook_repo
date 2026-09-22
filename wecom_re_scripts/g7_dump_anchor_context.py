import pefile
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PE = r"D:\Cursor_env\企业微信\WXWork\WXWork.exe"
IB = 0x400000
ANCHORS = [
    0x0BC491A1,  # SendVoice
    0x0B40550F,  # send_voice
    0x0BC496EF,  # voice_time
    0x0B8D5D62,  # voice_time
    0x0B7E2835,  # ITEM_VOICE
]

pe = pefile.PE(PE, fast_load=True)


def read_window(va, before=160, after=260):
    for s in pe.sections:
        base = IB + s.VirtualAddress
        end = base + s.Misc_VirtualSize
        if base <= va < end:
            d = s.get_data()
            off = va - base
            b = max(0, off - before)
            e = min(len(d), off + after)
            return s.Name.rstrip(b"\x00").decode("ascii", errors="replace"), d[b:e]
    return "?", b""


for va in ANCHORS:
    sec, blob = read_window(va)
    print(f"\n=== VA 0x{va:08x} RVA 0x{va-IB:x} section={sec} ===")
    try:
        print(blob.decode("latin1", errors="replace"))
    except Exception:
        print(blob.hex())
