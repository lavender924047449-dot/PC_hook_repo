#!/usr/bin/env python3
# 全 section 找 4B VA 匹配。字符串可能通过全局指针间接引用。
import pefile,struct,sys
sys.stdout.reconfigure(encoding='utf-8')
pe = pefile.PE(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe', fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase

targets = {
    'skip unsupported content_type' : 0x0af347a8,
    'unsupported content_type'      : 0x0af33972,
    'unsupported sub_type'          : 0x0af0e6f0,
    'Skip unsupported sub message'  : 0x0aff1556,
    'convert_voice_to_text'         : 0x0af45f42,
    'VoiceTextInfo'                 : 0x0aeb1766,
}

sections = [(s.Name.rstrip(b'\x00').decode(errors='ignore'), s.VirtualAddress, s.get_data()) for s in pe.sections]
for name, va in targets.items():
    raw = struct.pack('<I', va)
    print(f'\n[{name}]  VA=0x{va:x}')
    for sname, srva, sdata in sections:
        hits=[]; start=0
        while True:
            i=sdata.find(raw,start)
            if i<0: break
            hits.append(srva+i); start=i+1
            if len(hits)>=8: break
        if hits:
            print(f'   {sname:<10} {len(hits)} hit(s):  ' + ', '.join(f'RVA=0x{h:08x}' for h in hits))
