import json
from pathlib import Path
OUT=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
def hx(n): return bytes.fromhex(json.loads((OUT/n).read_text())["tasks"][0]["pkg_hex"])
v,f=hx("pkg_layout_voice_20260913_181713.json"),hx("pkg_layout_file_20260913_183259.json")
for start in range(0xe0,0x180,16):
    chunk_v=v[start:start+16]; chunk_f=f[start:start+16]
    if chunk_v!=chunk_f:
        print(f"+0x{start:03x} V:{chunk_v.hex()} F:{chunk_f.hex()}")
