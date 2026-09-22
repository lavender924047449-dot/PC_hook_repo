# dump Inner Parse field1 string-read + jump table
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv = IB + s.VirtualAddress
        td = s.get_data()
        break
md = Cs(CS_ARCH_X86, CS_MODE_32)

def dump_rva(rva, nbyte=280, tag=''):
    va = IB + rva
    off = va - tv
    print('='*76)
    print(f'{tag}  RVA=0x{rva:x}')
    n = 0
    for insn in md.disasm(td[off:off+nbyte], va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}')
        n += 1
        if n > 70:
            break
    print()

dump_rva(0x16865e7, 220, 'Parse field1 path (tag 0x0a)')
# jump table at 0x1a86758 from earlier: jmp dword ptr [ecx*4 + 0x1a86758]
# that's VA, RVA = 0x1a86758 - IB
jt_rva = 0x1a86758 - IB
print(f'jump table RVA=0x{jt_rva:x} (if IB-relative decode)')
# the instruction was: ff 24 8d 58 67 a8 01  jmp dword ptr [ecx*4 + 0x1a86758]
# 0x1a86758 is absolute VA in file = IB + rva_table
table_va = 0x1a86758
table_rva = table_va - IB
off = table_va - tv
print(f'jump table at VA=0x{table_va:x} RVA=0x{table_rva:x}')
for i in range(4):
    dest = struct.unpack_from('<I', td, off + i*4)[0]
    print(f'  field{i+1} -> VA=0x{dest:x} RVA=0x{dest-IB:x}')

dump_rva(0x191c4c0 - 0x20, 80, 'near field6 WriteString caller 0x191c4c0')
