# Second pass: 0x3de1270 handler, jump table in .text, 0x1a7eac0, 0x5e9690
import pefile, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td, trva = IB + s.VirtualAddress, s.get_data(), s.VirtualAddress

def dump_rva(rva, tag, nb=200):
    va = IB + rva
    off = va - tv
    print(f'\n{"="*72}\n{tag}  RVA=0x{rva:x}')
    n = 0
    for insn in md.disasm(td[off:off+nb], va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}')
        n += 1
        if insn.mnemonic.startswith('ret') and n > 10:
            break
        if n > 55:
            print('  ...')
            break

# jump table at 0x41098f0 is actually in .text
jt_rva = 0x3d098f0
jt_va = IB + jt_rva
jt_off = jt_va - tv
print(f'=== jump table RVA=0x{jt_rva:x} in .text ===')
for i in range(11):
    if jt_off + i*4 + 4 > len(td):
        print(f'  [{i}] out of bounds')
        continue
    entry = struct.unpack_from('<I', td, jt_off + i*4)[0]
    print(f'  [{i}] → VA=0x{entry:x} RVA=0x{entry-IB:x}')
    # peek first instruction
    e_off = entry - tv
    if 0 <= e_off < len(td):
        for insn in md.disasm(td[e_off:e_off+12], entry):
            print(f'       {insn.mnemonic} {insn.op_str}')
            break

dump_rva(0x3de1270, '0x3de1270 — type=2/3/4/5 handler')
dump_rva(0x167eac0, '0x1a7eac0 — called before ParseFromString')
dump_rva(0x1e9690, '0x5e9690 = string fn called with [src]+0x1b8')

# Also key: 0x990c080 called when type 2/3/5 and condition
dump_rva(0x990c080 - 0x400000, '0x990c080 — pre-alloc check')
dump_rva(0x57dde9b - 0x200, '0x57ddf30 tail before jmp 0x57ddf58')
