# disasm G3 parse_feed key callers
import pefile, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td = IB + s.VirtualAddress, s.get_data()

def pro(rva, mb=0x600):
    off = (IB + rva) - tv
    for b in range(mb):
        o = off - b
        if o < 1: break
        if td[o:o+3] == b'\x55\x8b\xec' and td[o-1] in (0xCC, 0xC3, 0x90):
            return o + (tv - IB)
        if o >= 3 and td[o:o+3] == b'\x55\x8b\xec' and td[o-3] == 0xC2:
            return o + (tv - IB)
    return rva

def dump(rva, tag, nb=220):
    va = IB + rva
    p = pro(rva)
    start = p
    off = (IB + start) - tv
    print(f'\n{"="*72}\n{tag}  hit=0x{rva:x}  pro=0x{start:x}')
    n = 0
    for insn in md.disasm(td[off:off+nb], IB + start):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        m = ' <<<' if insn.address - IB == rva else ''
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}{m}')
        n += 1
        if insn.mnemonic.startswith('ret') and n > 10: break
        if n > 55: print('  ...'); break

# 1) 大 ReadString 路径
dump(0x7c9ae38, 'outer proto Parse bt[7] 0x7c9ae38')
dump(0x75bee9e, 'outer proto dispatcher bt[6] 0x75bee9e')
dump(0x7c9bf9c, 'ReadString bytes into dst bt[0] 0x7c9bf9c')

# 2) COW caller
dump(0x7cfb107, 'COW field-assign bt[0] 0x7cfb107')
dump(0x3d1537b, 'COW caller bt[1] 0x3d1537b')

# 3) 唯一入口之一
dump(0x57ddf30, 'Parse caller A bt[3] 0x57ddf30')
dump(0x9ba6292, 'Parse chain bt[4] 0x9ba6292')
dump(0x992c1c4, 'Parse chain bt[5] 0x992c1c4')

# 4) frequent Parse callers
dump(0x7d1a385, 'Parse caller B 0x7d1a385')
dump(0x7d15ffe, 'Parse caller C 0x7d15ffe')
dump(0x7cfaea6, 'Parse caller D 0x7cfaea6')

# 5) 3d094fe path
dump(0x3d094fe, 'Parse caller E 0x3d094fe')
