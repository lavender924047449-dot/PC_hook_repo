# xref ImageBase+RVA of live vtables + dump ctor-like methods
import pefile, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
LIVE_BASE = 0x5e0000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td, trva = IB + s.VirtualAddress, s.get_data(), s.VirtualAddress
        break

VTS = {
    'inner': 0xb065434,
    'body':  0xb0653d4,
}

def xref(imm, label, limit=25):
    raw = struct.pack('<I', imm)
    print(f'\n=== xref {label} imm=0x{imm:x} ===')
    off, n = 0, 0
    hits = []
    while n < limit:
        i = td.find(raw, off)
        if i < 0:
            break
        start = max(0, i-10)
        ins = None
        for d in md.disasm(td[start:i+6], tv+start):
            if d.address <= tv+i < d.address+d.size:
                ins = d
                break
        rva = trva + i
        txt = f'wx+0x{rva:x}'
        if ins:
            txt += f'  {ins.mnemonic} {ins.op_str}'
        print('   ', txt)
        hits.append(rva)
        n += 1
        off = i + 1
    if n == 0:
        print('    (none)')
    return hits

for name, live in VTS.items():
    rva = live - LIVE_BASE
    file_va = IB + rva
    print(f'{name}: live=0x{live:x} rva=0x{rva:x} file_va=0x{file_va:x}')
    xref(file_va, name)

# also xref empty-string sentinel used in Parse: 0xf78d940
# that's a live VA. rva = 0xf78d940 - 0x5e0000 = 0xf1ad940
print('\nempty-str sentinel live 0xf78d940')
sent_rva = 0xf78d940 - LIVE_BASE
print(f'  rva=0x{sent_rva:x} file_va=0x{IB+sent_rva:x}')
xref(IB + sent_rva, 'empty string singleton')
