# Read switch table + disasm 0x80eae00 and surrounding context
import pefile, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td = IB + s.VirtualAddress, s.get_data()

def dump_rva(rva, tag, nb=200):
    va = IB + rva
    off = va - tv
    if off < 0 or off + nb > len(td):
        print(f'[skip] {tag}'); return
    print(f'\n{"="*72}\n{tag}  RVA=0x{rva:x}')
    n = 0
    for insn in md.disasm(td[off:off+nb], va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}')
        n += 1
        if insn.mnemonic.startswith('ret') and n > 10:
            break
        if n > 55: print('  ...'); break

# 1) switch table at 0x4109908 (in .text)
st_rva = 0x3d09908
st_va = IB + st_rva
st_off = st_va - tv
print('=== switch table RVA=0x3d09908 (11 entries) ===')
for i in range(11):
    v = td[st_off + i]
    print(f'  input[{i}] → branch_idx={v}')

# 2) 0x80eae00 — called after TextMessage parse, returns message type
dump_rva(0x80eae00 - IB, '0x80eae00 — returns message type from esi')

# 3) 0x41107b0 — fallback for non-0x2761 type
dump_rva(0x41107b0 - IB, '0x41107b0 — fallback type handler')

# 4) the function CONTAINING 0x4fbfe2 (the one that calls 0x3d094fe)
# look back from 0x4fbfe2 to find prologue
rva = 0x4fbfe2
for b in range(0x600, 0, -1):
    r = rva - b
    off = (IB + r) - tv
    if off < 0: continue
    if td[off:off+3] == b'\x55\x8b\xec' and (b > 5 and td[off-1] in (0xCC, 0xC3, 0x90)):
        print(f'\nFunction prologue found at rva=0x{r:x} (back {b})')
        dump_rva(r, f'function containing 0x4fbfe2  PRO=0x{r:x}', nb=300)
        break

# 5) 0x1a7db20 ctor in branch[3]
dump_rva(0x1a7db20 - IB, '0x1a7db20 — ctor used in branch[3]')
