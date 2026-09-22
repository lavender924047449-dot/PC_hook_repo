import pefile,sys
sys.stdout.reconfigure(encoding='utf-8')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
print('Machine=0x%x' % pe.FILE_HEADER.Machine)  # 0x14c=i386, 0x8664=AMD64
print('ImageBase=0x%x' % pe.OPTIONAL_HEADER.ImageBase)
print('Characteristics=0x%x' % pe.FILE_HEADER.Characteristics)
print('DllCharacteristics=0x%x' % pe.OPTIONAL_HEADER.DllCharacteristics)  # bit0x0040 = DYNAMIC_BASE (ASLR)
print('Sections:')
for s in pe.sections:
    print(f'  {s.Name.rstrip(chr(0).encode()).decode():<10} RVA=0x{s.VirtualAddress:08x}  VSize=0x{s.Misc_VirtualSize:08x}  RawSize=0x{s.SizeOfRawData:08x}')
