import json, struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

data = json.load(open('metadata_deep_20260911_184641.json', encoding='utf-8'))
TARGET = bytes.fromhex('4c43790b4465c9253865c9255843790b')

for r in data:
    print(f"TASK {r['begin']} tag4={r['tag4']!r} subcount={r['u32_1']}")
    for d in r.get('deep', []):
        bs = bytes(d['bytes'])
        if TARGET[:8] in bs:
            print(f"  HIT {d['ptr']} from {d['fromOff']}")
            print(f"   hex128: {bs[:128].hex()}")
            for i in range(0, min(len(bs), 128), 4):
                v = struct.unpack_from('<I', bs, i)[0]
                if 100000 < v < 500000000:
                    print(f"    [{i:3d}] {v} (0x{v:x})")

print('\n--- tag4 ---')
for r in data:
    meta = bytes(r['meta'])
    mo = r['magicOff']
    tag_bytes = meta[mo+24:mo+28] if mo >= 0 else b''
    print(f"  {r['begin']} tag4={r['tag4']!r} raw={tag_bytes.hex()} sub={r['u32_1']}")
