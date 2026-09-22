# Inner class region: type name + set_field1 (or [this+8],1) + hotpatch ctor E8
import pefile, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_32)
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.text':
        tv, td = IB + s.VirtualAddress, s.get_data()
        break
rdata = None
for s in pe.sections:
    if s.Name.rstrip(b'\x00') == b'.rdata':
        rdata = (IB + s.VirtualAddress, s.get_data(), s.VirtualAddress)

def dump_va(va, nbyte=80, tag=''):
    off = va - tv
    print(f'--- {tag} VA=0x{va:x} RVA=0x{va-IB:x} ---')
    n = 0
    for insn in md.disasm(td[off:off+nbyte], va):
        raw = ' '.join(f'{b:02x}' for b in insn.bytes)
        print(f'  {insn.address:08x} rva+{insn.address-IB:x}  {raw:<22} {insn.mnemonic} {insn.op_str}')
        n += 1
        if insn.mnemonic.startswith('ret') or n > 25:
            break
    print()

def cstr_at_fileva(va, n=64):
    rva = va - IB
    rv, rd, rr = rdata
    if rr <= rva < rr + len(rd):
        blob = rd[rva-rr:rva-rr+n]
        z = blob.find(b'\x00')
        s = blob[:z if z>=0 else n]
        print(f'  str @0x{va:x}: {s!r}  hex={s.hex()}')
    else:
        print(f'  not in rdata rva=0x{rva:x}')

print('=== type-name literals ===')
cstr_at_fileva(0xae79d6c)
cstr_at_fileva(0xae85610)
# RTTI after inner vt 0xae85434+0x44
cstr_at_fileva(0xae85434 + 0x44)
cstr_at_fileva(0xae85478)
# nearby names
for va in range(0xae85380, 0xae85680, 4):
    pass

# dump a window of ascii around inner vtable
rv, rd, rr = rdata
off = (0xae85434 - IB) - rr
window = rd[off:off+0x80]
print('inner vt+0 ascii window:', window)

dump_va(IB+0x16869e0, 64, 'vt[+8] exact 0x16869e0')
dump_va(0x1a7d770, 90, 'GetTypeName helper 0x167d770')

# search or dword [r+8], 1  in inner class ~0x167e000-0x1689000
print('=== or [xxx+8], 1  in 0x167e000-0x1689000 ===')
start_rva, end_rva = 0x167e000, 0x1689000
off0 = (IB + start_rva) - tv
chunk = td[off0: (IB+end_rva)-tv]
# 83 4? 08 01  = or dword ptr [reg+8], 1  (modrm)
# 83 4e 08 01 esi
# 83 4f 08 01 edi
# 83 48 08 01 eax
# 83 49 08 01 ecx
for i, b in enumerate(chunk[:-3]):
    if chunk[i]==0x83 and chunk[i+2]==0x08 and chunk[i+3]==0x01:
        modrm = chunk[i+1]
        if (modrm & 0xC0) == 0x40 and (modrm & 0x38) == 0x08:  # or r/m32, imm8 ; dest [reg+disp8]
            rva = start_rva + i
            dump_va(IB+rva, 48, f'or [r+8],1 @ 0x{rva:x}')

# hotpatch ctor entries
print('=== bytes before default ctor / copy ctor ===')
for rva in (0x167ecc0, 0x167ecc2, 0x167ed90, 0x167ed92):
    off = (IB+rva)-tv
    print(f'  0x{rva:x}: {td[off:off+8].hex()}')

# E8 to hotpatch starts only in nearby 16MB (not whole .text)
print('\n=== nearby E8 to default ctor 0x167ed90/2 and copy 0x167ecc0/2 ===')
targets = {IB+0x167ed90, IB+0x167ed92, IB+0x167ecc0, IB+0x167ecc2}
scan_from, scan_to = 0x1500000, 0x1a00000
o0 = (IB+scan_from)-tv
region = td[o0:(IB+scan_to)-tv]
hits = {t: [] for t in targets}
i = 0
while i < len(region)-5:
    if region[i]==0xE8:
        rel = struct.unpack_from('<i', region, i+1)[0]
        dest = tv + o0 + i + 5 + rel
        if dest in hits and len(hits[dest]) < 15:
            hits[dest].append(scan_from + i)
        i += 5
        continue
    i += 1
for t, hs in hits.items():
    print(f'  dest RVA 0x{t-IB:x}: {len(hs)}  ' + ', '.join(f'0x{h:x}' for h in hs))
