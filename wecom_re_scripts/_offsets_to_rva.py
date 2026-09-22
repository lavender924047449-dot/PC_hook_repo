#!/usr/bin/env python3
# 把文件偏移转成 RVA (加 module base 就是运行时地址)
import pefile, sys
sys.stdout.reconfigure(encoding='utf-8')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IMG_BASE = pe.OPTIONAL_HEADER.ImageBase
print(f'ImageBase = 0x{IMG_BASE:x}')

offs = {
    'skip unsupported content_type' : 0x0ab339a8,
    'unsupported content_type'      : 0x0ab32b72,
    'unsupported sub_type'          : 0x0ab0d8f0,
    'Skip unsupported sub message'  : 0x0abf0756,
    'convert_voice_to_text'         : 0x0ab45142,
    '语音 UTF-8 @ [语音通话]'         : 0x0b7add9d,
    'VoiceTextInfo'                 : 0x0aab0966,
}
for name, foff in offs.items():
    rva = pe.get_rva_from_offset(foff)
    va = IMG_BASE + rva
    print(f'  0x{foff:08x}  →  RVA=0x{rva:08x}  VA=0x{va:08x}   {name}')
