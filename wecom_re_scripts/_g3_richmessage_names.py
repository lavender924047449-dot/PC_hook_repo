import pefile, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = 0x400000
for s in pe.sections:
    n = s.Name.rstrip(b'\x00')
    if n == b'.rdata':
        rd, rr = s.get_data(), s.VirtualAddress
    if n == b'.text':
        td, tv = s.get_data(), IB + s.VirtualAddress
md = Cs(CS_ARCH_X86, CS_MODE_32)

# all ww_richmessage.* names
needle = b'ww_richmessage.'
off = 0
print('=== ww_richmessage.* in rdata ===')
while True:
    i = rd.find(needle, off)
    if i < 0:
        break
    z = rd.find(b'\x00', i)
    s = rd[i:z]
    rva = rr + i
    print(f'  RVA=0x{rva:x}  {s.decode("ascii", "replace")}')
    off = i + 1

def dump_rva(rva, nb=100, tag=''):
    va = IB + rva
    off = va - tv
    print(f'\n--- {tag} rva=0x{rva:x} ---')
    n = 0
    for insn in md.disasm(td[off:off+nb], va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}')
        n += 1
        if insn.mnemonic.startswith('ret') or n > 28:
            break

dump_rva(0x167cdec, 90, 'New()? caller of default ctor')
dump_rva(0x167d8f3, 90, 'New()? caller 2 of default ctor')
dump_rva(0x5e9364, 80, 'std::string assign(ptr,n) 0x5e9364')
dump_rva(0x7ff450, 60, 'string COW attach 0x7ff450')
