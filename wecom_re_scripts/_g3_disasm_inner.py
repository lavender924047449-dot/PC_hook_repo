import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv = IB + s.VirtualAddress
        td = s.get_data()
        break
md = Cs(CS_ARCH_X86, CS_MODE_32)

def pro(rva, mb=0x800):
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

def dump(rva, tag, maxb=450):
    va = IB + rva
    p = pro(rva)
    start = p or (va - 16)
    print('=' * 76)
    print(f'{tag}  hit=0x{rva:x}  pro_rva=0x{(start-IB):x}')
    off = start - tv
    n = 0
    for insn in md.disasm(td[off:off+maxb], start):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        m = ' <<<' if insn.address == va else ''
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}{m}')
        n += 1
        if insn.mnemonic == 'ret' and n > 12:
            break
        if n > 75:
            print(' ...')
            break
    print()

for rva, tag in [
    (0x1687420, 'INNER WriteString caller field1=[语音]'),
    (0x7c9c53e, 'OUTER field5 body wrapper'),
    (0x2a42f9, 'common bt 0x2a42f9'),
    (0x2a3699, 'common bt 0x2a3699'),
]:
    dump(rva, tag)
