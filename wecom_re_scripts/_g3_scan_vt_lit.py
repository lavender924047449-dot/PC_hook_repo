# Fix: runtime VA 0xb065434 = ImageBase 0x400000 + RVA 0xac65434
# Also dump 语音 literals and xref vtable / string VAs in .text
import pefile, struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

EXE = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
pe = pefile.PE(EXE, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
print(f'ImageBase=0x{IB:x}')

secs = {}
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1', 'replace')
    secs[name] = (IB + s.VirtualAddress, s.get_data(), s.VirtualAddress, s.SizeOfRawData)
    print(f'  {name:8s} RVA=0x{s.VirtualAddress:08x} VA=0x{IB+s.VirtualAddress:08x} size=0x{s.SizeOfRawData:x}')

md = Cs(CS_ARCH_X86, CS_MODE_32)

def data_at_rva(rva, n=64):
    for name, (va, data, srva, sz) in secs.items():
        if srva <= rva < srva + len(data):
            off = rva - srva
            return name, data[off:off+n]
    return None, None

def dump_vt(va, n=20):
    rva = va - IB
    name, blob = data_at_rva(rva, n*4)
    print(f'\n=== vtable VA=0x{va:x} RVA=0x{rva:x} section={name} ===')
    if not blob:
        print('  NOT IN FILE')
        return
    for i in range(n):
        slot = struct.unpack_from('<I', blob, i*4)[0]
        slot_rva = (slot - IB) & 0xffffffff if slot >= IB else slot
        print(f'  [{i:2d}] va=0x{slot:08x}  rva=0x{slot_rva:x}')

# runtime VTs from dumps
dump_vt(0x0b065434, 20)  # inner proto this[0]
dump_vt(0x0b0653d4, 20)  # body this[0] from this_hex d453060b
dump_vt(0x0b0656a8, 20)  # previously assumed body wrapper

# Inner Serialize should appear in some vtable
SER = IB + 0x1687402
PARSE = IB + 0x16864d2
print(f'\n=== search .rdata for Serialize VA=0x{SER:x} / Parse VA=0x{PARSE:x} ===')
rdata_va, rdata, rdata_rva, _ = secs['.rdata']
needle_ser = struct.pack('<I', SER)
needle_parse = struct.pack('<I', PARSE)
for label, needle in [('Serialize', needle_ser), ('Parse', needle_parse)]:
    off = 0
    hits = []
    while len(hits) < 15:
        i = rdata.find(needle, off)
        if i < 0:
            break
        hits.append(rdata_rva + i)
        off = i + 4
    print(f'  {label}: {len(hits)} hits  RVAs=' + ', '.join(f'0x{h:x}' for h in hits))

print('\n=== 语音 literal context ===')
VOICE = bytes.fromhex('e8afade99fb3')
for name, (va, data, srva, sz) in secs.items():
    off = 0
    while True:
        i = data.find(VOICE, off)
        if i < 0:
            break
        rva = srva + i
        ctx = data[max(0, i-16):i+24]
        # printable
        def vis(b):
            return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)
        print(f'  {name} RVA=0x{rva:x} VA=0x{IB+rva:x}')
        print(f'    hex={ctx.hex()}')
        print(f'    ascii={vis(ctx)}')
        try:
            print(f'    utf8={ctx.decode("utf-8", "replace")!r}')
        except Exception:
            pass
        off = i + 1

# xref imm32 in .text
text_va, text, text_rva, _ = secs['.text']

def xref_imm(imm, label, limit=25):
    raw = struct.pack('<I', imm)
    print(f'\n=== .text xref {label} imm=0x{imm:x} ===')
    off = 0
    n = 0
    while n < limit:
        i = text.find(raw, off)
        if i < 0:
            break
        start = max(0, i - 8)
        decoded = list(md.disasm(text[start:i+6], text_va + start))
        ins = None
        for d in decoded:
            if d.address <= text_va + i < d.address + d.size:
                ins = d
                break
        rva = text_rva + i
        if ins:
            print(f'  RVA=0x{rva:x}  {ins.mnemonic} {ins.op_str}')
        else:
            print(f'  RVA=0x{rva:x}  (undecoded)')
        n += 1
        off = i + 1
    if n == 0:
        print('  (none)')

# ctors store ImageBase-relative VA of vtable
xref_imm(0x0b065434, 'inner vt')
xref_imm(0x0b0653d4, 'body vt from dump')
xref_imm(0x0b0656a8, 'old body vt guess')

# string VAs for 语音 hits (print after we know them; hardcode from previous scan)
for rva in (0xaea0d5c, 0xb7469e7, 0xb7aeb9d):
    xref_imm(IB + rva, f'语音 @ rva 0x{rva:x}')
