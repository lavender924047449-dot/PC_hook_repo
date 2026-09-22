import json
from pathlib import Path
data = json.loads(Path(r"runtime/wecom_re/voice_ctor_hunt_20260913_223335.json").read_text())
ctors = data["ctors"]["ctors"]
for i, c in enumerate(ctors):
    rva = c["func_rva"]
    ctx = c["context"]
    delta = c["delta_from_ref"]
    frame = c.get("frame_size")
    ref = c["ref_rva"]
    prev = c["prev_byte"]
    bh = c.get("bytes_hex", "")
    print(f"=== [{i}] func_rva={rva}  context={ctx}  delta={delta}  frame={frame}")
    print(f"    ref_rva={ref}  prev_byte={prev}")
    # every 2 hex = 1 byte; print 64 bytes (128 hex chars)
    print(f"    bytes[0:64]: {bh[:128]}")
    print()

sr = data["str_refs"]["silk"]
print(f"SILK hits: {sr['count']}")
for loc in sr["locs"]:
    print(f"  rva={loc['rva']}  ctx={loc['ctx'][:80]}")

vr = data["str_refs"]["VoiceRecord"]
print(f"\nVoiceRecord hits: {vr['count']}")
for loc in list(vr["locs"])[:8]:
    print(f"  rva={loc['rva']}")
