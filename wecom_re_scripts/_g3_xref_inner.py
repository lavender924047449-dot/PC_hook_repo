# xref E8/E9 to inner Parse/Serialize
import pefile, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv = IB + s.VirtualAddress
        td = s.get_data()
        break

TARGETS = {
    'Parse 0x16864d2': 0x16864d2,
    'Serialize 0x1687402': 0x1687402,
}

def find_calls(target_rva, limit=25):
    tva = IB + target_rva
    hits = []
    i = 0
    while i < len(td) - 5:
        if td[i] == 0xE8:
            rel = struct.unpack_from('<i', td, i+1)[0]
            dest = tv + i + 5 + rel
            if dest == tva:
                hits.append(tv + i - IB)
                if len(hits) >= limit:
                    break
            i += 5
            continue
        i += 1
    return hits

for name, rva in TARGETS.items():
    hs = find_calls(rva)
    print(f'{name}  {len(hs)} direct E8 (showing {min(12,len(hs))}):')
    for h in hs[:12]:
        print(f'    caller_insn RVA=0x{h:x}')
    print()
