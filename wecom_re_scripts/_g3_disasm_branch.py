# disasm key branch sites: 0x57ddf58 (type=4 path), IAT call context, 0x5e9690,
# also 0x3d094fe jump table, 0x75c214b, 0x1a7eac0
import pefile, sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td = IB + s.VirtualAddress, s.get_data()
    if s.Name.rstrip(b'\x00') == b'.rdata':
        rv, rd, rrva = IB + s.VirtualAddress, s.get_data(), s.VirtualAddress

def dump_rva(rva, tag, nb=240):
    va = IB + rva
    off = va - tv
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

# 1) 0x57ddf30 跳转目标 type=4 branch
dump_rva(0x57ddf58, '0x57ddf30 type=4 branch target')

# 2) 继续 0x57ddf30 正文 (TextMessage 之后做了什么)
dump_rva(0x57dde00, '0x57ddf30 after TextMessage ctor body')

# 3) 0x3d094fe jump table contents
jt_va = 0x41098f0
jt_rva = jt_va - IB
jt_off = jt_rva - rrva
print(f'\n=== jump table @ 0x{jt_va:x} rva=0x{jt_rva:x} ===')
for i in range(11):
    entry = struct.unpack_from('<I', rd, jt_off + i*4)[0]
    print(f'  [{i}] → VA=0x{entry:x} RVA=0x{entry-IB:x}')
# dump each branch
for i in range(11):
    entry = struct.unpack_from('<I', rd, jt_off + i*4)[0]
    rva = entry - IB
    va = entry
    off = va - tv
    if off < 0 or off >= len(td):
        print(f'  branch[{i}] out of .text')
        continue
    n = 0
    first = None
    for insn in md.disasm(td[off:off+30], va):
        if first is None:
            first = insn
        n += 1
        if n >= 3:
            break
    if first:
        print(f'  branch[{i}] rva=0x{rva:x}:  {first.mnemonic} {first.op_str}')

# 4) 0x5e9690 — what string fn is this
dump_rva(0x1e9690, '0x5e9690 (string fn called in 0x57ddf30)')

# 5) 0x1a7eac0 — called in Parse caller C before ParseFromString
dump_rva(0x167eac0, '0x1a7eac0 called before ParseFromString')

# 6) IAT at 0xac00c7c — what DLL
iat_off = 0xac00c7c - IB - rrva
if 0 <= iat_off < len(rd):
    ptr = struct.unpack_from('<I', rd, iat_off)[0]
    print(f'\nIAT 0xac00c7c → 0x{ptr:x}')

# 7) 0x75c214b
dump_rva(0x75c214b - 0x50, '0x75c214b context (-0x50)')

# 8) 0x5bddf58 — type=4 handler further
dump_rva(0x57ddf58 + 0x30, '0x57ddf58 +0x30')
