import json, struct
from pathlib import Path
OUT=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
def hx(name):
    return bytes.fromhex(json.loads((OUT/name).read_text())["tasks"][0]["pkg_hex"])
v,f=hx("pkg_layout_voice_20260913_181713.json"),hx("pkg_layout_file_20260913_183259.json")
for start in range(0x40,0x80,4):
    print(f"+0x{start:03x}: voice={struct.unpack_from('<I',v,start)[0]:#10x}  file={struct.unpack_from('<I',f,start)[0]:#10x}")
print("\ndiff 0x40-0x180:")
for i in range(0x40,0x180):
    if v[i]!=f[i]:
        print(f" +0x{i:03x} v={v[i]:02x} f={f[i]:02x}")
