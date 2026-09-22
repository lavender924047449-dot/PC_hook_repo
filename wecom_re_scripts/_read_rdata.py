# _read_rdata.py — 从 WXWork.exe 里读任意 RVA 的字节（找 proto descriptor）
import sys, pefile
from pathlib import Path

WXWORK = Path(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe')
pe = pefile.PE(str(WXWORK), fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
print(f'image_base = 0x{IB:08x}')

def read_rva(rva, n):
    for s in pe.sections:
        va = s.VirtualAddress
        sz = max(s.SizeOfRawData, s.Misc_VirtualSize)
        if va <= rva < va + sz:
            off = rva - va
            data = s.get_data()[off:off+n]
            name = s.Name.rstrip(b'\x00').decode(errors='replace')
            return name, data
    return None, None

TARGETS = [
    ('a5 in A_d3 (ww_richmessage.Extra descriptor)', 0xb0901ac),
    ('a5-0x20 (前面看结构头)',                        0xb090180),
    ('a5-0x40',                                        0xb090160),
    # 一并读 X_d1 (0x09ba54f0) 里出现的 mMeetingJoinCheckReq
    ('mMeetingJoinCheckReq @ nearby',                  0x09ba54f0 - 0x100),
]
for name, rva in TARGETS:
    sec, data = read_rva(rva, 256)
    if data is None: print(f'{name}: RVA 0x{rva:08x} not in any section'); continue
    print(f'\n== {name}  RVA=0x{rva:08x}  section={sec}  ==')
    # ascii
    a = ''.join(chr(b) if 32<=b<127 else '.' for b in data)
    # hex 32B/line
    for i in range(0, len(data), 32):
        chunk = data[i:i+32]
        h = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f'  {rva+i:08x}  {h}  {asc}')
