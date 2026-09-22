# Disasm: actual media handler (type 2/3/5) RVA 0x39e1270,
# jump table branches of 0x3d094fe, and 0x57ddf30 source msg struct at +0x1b8
import pefile, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td, trva = IB + s.VirtualAddress, s.get_data(), s.VirtualAddress

def dump_rva(rva, tag, nb=240):
    va = IB + rva
    off = va - tv
    if off < 0 or off + nb > len(td):
        print(f'[skip] {tag} rva=0x{rva:x} out of range (off={off})')
        return
    print(f'\n{"="*72}\n{tag}  RVA=0x{rva:x}')
    n = 0
    for insn in md.disasm(td[off:off+nb], va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}')
        n += 1
        if insn.mnemonic.startswith('ret') and n > 8:
            break
        if n > 60:
            print('  ...')
            break

def rva_from_va(va):
    """Call target VA → RVA (subtract IB)"""
    return va - IB

# 1) actual media handler - call target VA from disasm is 0x3de1270 (but was 0x03de1270 ?)
# from: e8 91 32 20 fe at VA 0x05bddfd9: next_ip = 0x05bddfe3 - rel32 signed
# rel32 = 0xfe203291 (LE) → signed = -32,341,871
# target VA = 0x05bddfe3 + 0xFE203291 mod 2^32
raw_rel = 0xfe203291
next_ip = 0x05bddfe3  # From disasm output
target_va = (next_ip + raw_rel) & 0xFFFFFFFF
print(f'call target VA: 0x{target_va:08x}  RVA: 0x{target_va - IB:x}')
dump_rva(target_va - IB, 'media-handler (type 2/3/4/5) target of call at 0x5bddfd9')

# 2) Jump table branches for 0x3d094fe
jt_rva = 0x3d098f0
jt_va = IB + jt_rva
jt_off = jt_va - tv
print(f'\n=== 0x3d094fe jump table branches (full) ===')
valid_entries = []
for i in range(6):
    entry = struct.unpack_from('<I', td, jt_off + i*4)[0]
    r = entry - IB
    valid_entries.append(r)
    print(f'  [{i}] VA=0x{entry:x}  RVA=0x{r:x}')
for i, r in enumerate(valid_entries):
    dump_rva(r, f'0x3d094fe branch[{i}]', nb=120)

# 3) Who calls 0x57ddf30?  Frida trace shows bt[4]=wx+0x4fbfe2 
dump_rva(0x4fbfe2, '0x4fbfe2 - caller of 0x57ddf30')

# 4) 0x57ddf30 callee at vtable[1] check: IAT at 0xac00c7c
iat_off = (IB + 0xac00c7c) - tv  # if .text contains IAT data, otherwise separate
print(f'\nIAT @ rva 0xac00c7c: offset in .text = {iat_off}')
# Check if it's in .rdata instead
for s in pe.sections:
    rva_s = s.VirtualAddress
    size = s.SizeOfRawData
    if rva_s <= 0xac00c7c < rva_s + size:
        raw_off = 0xac00c7c - rva_s
        val = struct.unpack_from('<I', s.get_data(), raw_off)[0]
        sname = s.Name.rstrip(b'\x00')
        print(f'  Section {sname} off={raw_off} value=0x{val:x}')
        break
