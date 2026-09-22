# disasm inner proto ctors + E8 callers + GetTypeName
import pefile, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td, trva = IB + s.VirtualAddress, s.get_data(), s.VirtualAddress
        break

def pro(rva, mb=0x400):
    off = (IB + rva) - tv
    for b in range(mb):
        o = off - b
        if o < 1:
            break
        if td[o:o+3] == b'\x55\x8b\xec' and td[o-1] in (0xCC, 0xC3, 0x90):
            return tv + o
        if o >= 3 and td[o:o+3] == b'\x55\x8b\xec' and td[o-3] == 0xC2:
            return tv + o
    return None

def dump(rva, tag, maxb=220):
    va = IB + rva
    p = pro(rva)
    start = p or (va - 8)
    print('='*76)
    print(f'{tag}  hit=0x{rva:x}  pro=0x{start-IB:x}')
    off = start - tv
    n = 0
    for insn in md.disasm(td[off:off+maxb], start):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        m = ' <<<' if insn.address == va else ''
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}{m}')
        n += 1
        if insn.mnemonic == 'ret' and n > 8:
            break
        if n > 55:
            print('  ...')
            break
    print()
    return start - IB

def find_e8(target_rva, limit=20):
    tva = IB + target_rva
    hits = []
    i = 0
    n = 0
    while i < len(td) - 5 and n < limit:
        if td[i] == 0xE8:
            rel = struct.unpack_from('<i', td, i+1)[0]
            dest = tv + i + 5 + rel
            if dest == tva:
                hits.append(trva + i)
                n += 1
                i += 5
                continue
        i += 1
    return hits

# GetTypeName / metadata
dump(0x16869e0, 'inner vt[+8] likely GetTypeName')
dump(0x1681100, 'inner vt[+18] likely Clear')
dump(0x1682680, 'inner vt[+4] dtor-deleting?')

ctors = []
for rva, tag in [
    (0x167ecfa, 'inner vt write #1'),
    (0x167edbd, 'inner vt write #2'),
    (0x167f1ef, 'inner vt write #3'),
    (0x167f852, 'inner vt write #4 (near dtor 0x167f840)'),
]:
    pro_rva = dump(rva, tag)
    ctors.append((rva, pro_rva, tag))

print('\n===== E8 callers of ctor prologues (unique) =====')
seen = set()
for rva, pro_rva, tag in ctors:
    if pro_rva in seen:
        continue
    seen.add(pro_rva)
    hs = find_e8(pro_rva)
    print(f'\n{tag}  entry=0x{pro_rva:x}  E8_count~{len(hs)} (cap 20)')
    for h in hs:
        print(f'    call @ wx+0x{h:x}')
