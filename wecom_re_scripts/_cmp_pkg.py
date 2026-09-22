import json, struct
from pathlib import Path
OUT = Path(__file__).resolve().parent

d  = json.loads((OUT / "m3_hijack_20260913_224333.json").read_text())
ph = bytes.fromhex(d["events"][0]["pkg_hex"])
v  = bytes.fromhex(json.loads((OUT/"pkg_layout_voice_20260913_181713.json").read_text())["tasks"][0]["pkg_hex"])
f  = bytes.fromhex(json.loads((OUT/"pkg_layout_file_20260913_183259.json").read_text())["tasks"][0]["pkg_hex"])

print("=== PACKAGE +0x00..+0x60 (16B/row) ===")
for off in range(0, min(0x60, len(ph)), 16):
    prow = ph[off:off+16].hex(" ")
    vrow = v[off:off+16].hex(" ") if off+16 <= len(v) else "?" * 48
    frow = f[off:off+16].hex(" ") if off+16 <= len(f) else "?" * 48
    print(f"+{off:03x}:  pat={prow}")
    print(f"         v  ={vrow}")
    print(f"         f  ={frow}")
    print()

print("=== BYTE DIFF: patched vs voice (+0x00..+0x1b0, excluding +0x1b8 body area) ===")
diffs = []
for i in range(min(0x1b0, len(ph), len(v))):
    if ph[i] != v[i]:
        fi = f"{f[i]:02x}" if i < len(f) else "--"
        diffs.append(f"  +0x{i:03x}: patched={ph[i]:02x}  voice={v[i]:02x}  file={fi}")
print(f"Total diffs: {len(diffs)}")
for d2 in diffs[:40]:
    print(d2)
