import pefile,struct,sys
sys.stdout.reconfigure(encoding='utf-8')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
print(f'IB=0x{IB:x}')
data = open(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe','rb').read()
# 在整个 file 里找 "skip unsupported content_type"
needle = b'skip unsupported content_type'
i = data.find(needle)
print(f'  file_off=0x{i:08x}')
rva = pe.get_rva_from_offset(i)
print(f'  RVA=0x{rva:08x}  VA=0x{IB+rva:08x}')
# 定位在哪个 section
for s in pe.sections:
    if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
        print(f'  in section: {s.Name.rstrip(chr(0).encode()).decode()}')
        break

# 再验证：搜 VA
va = IB+rva
raw = struct.pack('<I', va)
print(f'  search 4B={raw.hex()}')
n = data.count(raw)
print(f'  4B count in whole file: {n}')
# 试列表若干位置
locs=[]; start=0
while True:
    j = data.find(raw, start)
    if j<0: break
    locs.append(j); start=j+1
    if len(locs)>=20: break
print(f'  first 20 file positions: {[hex(x) for x in locs]}')
# 再试直接找 "unsupported" 附近的其他 VA
