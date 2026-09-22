import pefile, struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
base_live = 0x5e0000
vt_live = 0xb065434
rva = vt_live - base_live
print(f'IB=0x{IB:x} live_base=0x{base_live:x} vt_live=0x{vt_live:x} rva=0x{rva:x}')

def dump_rva(rva, n=20):
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('latin1','replace')
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.SizeOfRawData, s.Misc_VirtualSize):
            off = rva - s.VirtualAddress
            data = s.get_data()
            print(f'  in {name} off=0x{off:x}')
            for i in range(n):
                slot = struct.unpack_from('<I', data, off+i*4)[0]
                slot_rva = (slot - IB) & 0xffffffff
                print(f'    [{i:2d}] +0x{i*4:02x}  file_va=0x{slot:08x}  as_rva=0x{slot_rva:x}')
            return
    print('  not in any section')

print('--- file dump vt rva ---')
dump_rva(rva)
print('--- file dump 0xb0653d4 rva ---')
dump_rva(0xb0653d4 - base_live)
