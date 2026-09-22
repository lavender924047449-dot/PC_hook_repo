# scan_disk_tag4.py — 离线扫描 WXWork.exe 磁盘镜像（reverse-engineering 静态阶段）
import struct, sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WX = Path(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe')
if not WX.exists():
    # fallback search
    for p in Path(r'D:\Cursor_env\企业微信').rglob('WXWork.exe'):
        WX = p
        break

print(f'File: {WX} ({WX.stat().st_size//1024//1024} MB)')
data = WX.read_bytes()

NEEDLES = [
    b'WbWC', b'W1pd', b'417+', b'ZSBQ',
    b'ForwardMessage', b'forward_msg', b'ForwardMessageReq',
    bytes([0xd0, 0x07, 0x00, 0x02]),
    bytes([0x4c, 0x43, 0x79, 0x0b]),  # payload desc magic
]

for nd in NEEDLES:
    offs = []
    start = 0
    while True:
        i = data.find(nd, start)
        if i < 0:
            break
        offs.append(i)
        start = i + 1
        if len(offs) >= 20:
            break
    label = nd.decode('latin-1', errors='replace') if nd.isascii() or len(nd) <= 4 else nd.hex()
    print(f'\n{label!r}: {len(offs)} hits')
    for off in offs[:8]:
        rva = off  # file offset ~ rva for PE without rebase info; note ASLR at runtime
        ctx = data[max(0,off-8):off+len(nd)+16]
        print(f'  file_off=0x{off:08x} ctx={ctx.hex()}')

# search pointer-like xrefs to file offsets of WbWC if found
wb = [i for i in range(len(data)-3) if data[i:i+4] == b'WbWC']
if wb:
    va_guess = wb[0]  # rough
    pat = struct.pack('<I', va_guess)
    print(f'\nSearching LE ptr to file_off 0x{va_guess:x}...')
    refs = []
    start = 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        refs.append(i)
        start = i + 1
        if len(refs) >= 10:
            break
    print(f'  ptr refs in file: {len(refs)}')
    for r in refs:
        print(f'    file_off=0x{r:08x}')
