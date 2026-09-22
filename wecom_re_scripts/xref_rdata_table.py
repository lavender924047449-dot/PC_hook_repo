# xref_rdata_table.py — 在 WXWork.exe 磁盘镜像中搜 rdata CGI 表 (WbWC) 的 code xref
import struct, sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

WX = Path(r'D:\Cursor_env\企业微信\WXWork\WXWork.exe')
data = WX.read_bytes()
BASE = 0x2D0000

# 已知 file_off（≈RVA，此二进制映射接近 1:1 + base）
TABLE = {
    'WbWC': 0x0b7cffcc,
    '417+': 0x0b7cfeec,
    'W1pd': 0x0b7ce56c,
    'ZSBQ': 0x0b7cfd2c,
    'payload_magic': 0x07b86b35,  # 4c43790b in code
}

def find_refs(label, file_off):
    # 尝试多种 VA 编码：RVA 本身、BASE+RVA、BASE+file_off
    candidates = []
    rva = file_off
    for va in [rva, BASE + rva, file_off, BASE + file_off]:
        pat = struct.pack('<I', va & 0xFFFFFFFF)
        refs = []
        start = 0
        while True:
            i = data.find(pat, start)
            if i < 0:
                break
            # 过滤 rdata 自引用
            if 0x0a000000 < i < 0x0cb00000 and label != 'self':
                pass
            refs.append(i)
            start = i + 1
            if len(refs) >= 15:
                break
        if refs:
            candidates.append((va, pat.hex(), refs))
    return candidates

print(f'Scanning {WX.name} ({len(data)//1024//1024} MB), BASE=0x{BASE:x}\n')

for label, off in TABLE.items():
    print(f'=== {label} file_off=0x{off:08x} ===')
    # show context string
    ctx = data[off-16:off+32]
    try:
        s = ctx.decode('utf-8', errors='replace')
        print(f'  context: {repr(s[:60])}')
    except Exception:
        print(f'  hex: {ctx.hex()}')

    refs = find_refs(label, off)
    if not refs:
        print('  xref: 0 (direct LE ptr)')
    for va, pat, offs in refs:
        print(f'  VA=0x{va:08x} pat={pat} -> {len(offs)} refs')
        for r in offs[:8]:
            # 判断段
            seg = 'text' if r < 0x0a000000 else ('rdata' if r < 0x0cb00000 else 'other')
            snippet = data[r-4:r+8].hex()
            print(f'    file_off=0x{r:08x} ({seg}) snippet={snippet}')

# 额外：搜 WbWC 前后更大块，提取完整表项
print('\n=== WbWC 表项完整上下文 (256B) ===')
off = TABLE['WbWC']
block = data[off-64:off+192]
# 打印可打印字符
line = ''
for i, b in enumerate(block):
    if 32 <= b < 127:
        line += chr(b)
    else:
        if len(line) >= 4:
            print(f'  @{off-64+i-len(line)}: {line!r}')
        line = ''
if len(line) >= 4:
    print(f'  str: {line!r}')
