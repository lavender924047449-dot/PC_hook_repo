#!/usr/bin/env python3
# 在 .text 里找 `push <string_VA>` (0x68 XX XX XX XX) 定位 log/format 调用点
import pefile, struct, sys
sys.stdout.reconfigure(encoding='utf-8')
EXE = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
pe = pefile.PE(EXE, fast_load=True)
IMG_BASE = pe.OPTIONAL_HEADER.ImageBase

# 定位 .text
text_sec = next(s for s in pe.sections if s.Name.rstrip(b'\x00')==b'.text')
text_data = text_sec.get_data()
text_rva  = text_sec.VirtualAddress
text_size = len(text_data)
print(f'.text  RVA=0x{text_rva:x}  size={text_size:,}')

targets = {
    'skip unsupported content_type' : 0x0af347a8,
    'unsupported content_type'      : 0x0af33972,
    'unsupported sub_type'          : 0x0af0e6f0,
    'Skip unsupported sub message'  : 0x0aff1556,
    'convert_voice_to_text'         : 0x0af45f42,
    'VoiceTextInfo'                 : 0x0aeb1766,
}

for name, va in targets.items():
    # 先尝试裸 4B VA 匹配，把所有出现列出来
    raw = struct.pack('<I', va)
    all_hits=[]; start=0
    while True:
        i=text_data.find(raw, start)
        if i<0: break
        # 看前一字节的 opcode
        prev = text_data[i-1] if i>0 else 0
        all_hits.append((text_rva+i, prev)); start=i+1
        if len(all_hits)>=20: break
    if all_hits:
        print(f'\n[{name}]  target VA=0x{va:x}  raw-4B matches in .text = {len(all_hits)}')
        for rva,prev in all_hits[:12]:
            op = {0x68:'push imm32', 0xb9:'mov ecx,imm32', 0xba:'mov edx,imm32', 0xbe:'mov esi,imm32',
                  0xbf:'mov edi,imm32', 0xb8:'mov eax,imm32', 0x05:'add eax,imm32', 0x3d:'cmp eax,imm32'}.get(prev, f'prev=0x{prev:02x}')
            print(f'   @RVA=0x{rva:08x}   preceded by 0x{prev:02x}   ({op})')
    else:
        print(f'\n[{name}]  target VA=0x{va:x}  NO 4B match in .text')
    # 保留旧的 push 匹配
    needle = b'\x68' + struct.pack('<I', va)   # push imm32
    hits=[]; start=0
    while True:
        i=text_data.find(needle, start)
        if i<0: break
        rva = text_rva + i
        va_call = IMG_BASE + rva
        hits.append((rva, va_call))
        start=i+1
        if len(hits)>=20: break
    print(f'\n[{name}]  target VA=0x{va:x}  push xrefs={len(hits)}')
    for rva,va_c in hits[:10]:
        print(f'   push @RVA=0x{rva:08x}  VA=0x{va_c:08x}')
    # 也试 mov ecx,imm32 (opcode b9)
    needle2 = b'\xb9' + struct.pack('<I', va)
    hits2=[]; start=0
    while True:
        i=text_data.find(needle2, start)
        if i<0: break
        hits2.append(text_rva+i); start=i+1
        if len(hits2)>=20: break
    if hits2:
        print(f'   (mov ecx xrefs = {len(hits2)})')
        for rva in hits2[:5]:
            print(f'      @RVA=0x{rva:08x}')
