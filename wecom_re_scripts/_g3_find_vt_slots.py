# Search whole PE for Inner Serialize/Parse pointers (file uses ImageBase+RVA)
import pefile, struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
EXE = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
pe = pefile.PE(EXE, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase

TARGETS = {
    'Ser VA  IB+0x1687402': IB + 0x1687402,
    'Parse VA IB+0x16864d2': IB + 0x16864d2,
    'Ser RVA only': 0x1687402,
    'Parse RVA only': 0x16864d2,
    'BodySer VA': IB + 0x15a0de2,
    'WriteStr VA': IB + 0x9937f10,
}

for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1', 'replace')
    data = s.get_data()
    srva = s.VirtualAddress
    for label, val in TARGETS.items():
        raw = struct.pack('<I', val)
        hits = []
        off = 0
        while len(hits) < 12:
            i = data.find(raw, off)
            if i < 0:
                break
            hits.append(srva + i)
            off = i + 4
        if hits:
            print(f'{name}  {label}  (0x{val:x}): ' + ', '.join(f'0x{h:x}' for h in hits))

print('\ndone')
