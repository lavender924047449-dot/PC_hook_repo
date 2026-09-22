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

def pro(rva, mb=0xc00):
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

def dump(rva, tag, maxb=700):
    va = IB + rva
    p = pro(rva)
    start = p or (va - 16)
    print('=' * 76)
    print(f'{tag}  hit=0x{rva:x}  pro_rva=0x{(start-IB):x}  fn~{va-start:#x}B')
    off = start - tv
    n = 0
    for insn in md.disasm(td[off:off+maxb], start):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        m = ' <<<' if insn.address == va else ''
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}{m}')
        n += 1
        if insn.mnemonic == 'ret' and n > 15:
            break
        if n > 90:
            print(' ...')
            break
    print()

for rva, tag in [
    (0x1686735, 'InnerSer bt 0x1686735 (same class region)'),
    (0x4fbfe2, 'InnerSer bt 0x4fbfe2'),
    (0x9923cb6, 'generic SerializeToString? 0x9923cb6'),
    (0x99243a6, 'generic 0x99243a6'),
]:
    dump(rva, tag)
