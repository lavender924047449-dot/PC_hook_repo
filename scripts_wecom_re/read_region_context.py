"""
从 0x26311000 区域（包含多组 seq+ts 候选）读取上下文
分析这是否是 SQLite B-tree 叶页或消息缓存
"""
import ctypes, ctypes.wintypes, struct, json, pathlib
from datetime import datetime

PID = 20632
kernel32 = ctypes.windll.kernel32
hProc = kernel32.OpenProcess(0x0010 | 0x0400, False, PID)

def read_mem(addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value] if ok and n.value > 0 else None

def hexdump(data, base=0, row=16):
    lines = []
    for i in range(0, min(len(data), 256), row):
        chunk = data[i:i+row]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        lines.append(f'  {base+i:08x}  {h:<{row*3-1}}  {a}')
    return '\n'.join(lines)

# Read the region around 0x2659ddd8 (the clearest triplet)
# Read 512 bytes starting 256 bytes before
start = 0x2659ddd8 - 256
data = read_mem(start, 1024)
if data:
    print(f'=== Context around 0x2659ddd8 (seq=11498 ts=2023-11-24) ===')
    # Find SQLite B-tree signature (page type = 0x0D at 4096-byte aligned)
    for align in [0, 4096, 8192]:
        check_addr = start & ~(align-1) if align > 0 else start
        check_data = read_mem(check_addr, 16) if align > 0 else None
    
    print(hexdump(data, start))
    
    # Parse structure: scan for (u64_small, u64_ts) pattern
    print('\n=== Parsed uint64 values ===')
    for i in range(0, len(data)-8, 8):
        lo, hi = struct.unpack_from('<II', data, i)
        val = (hi << 32) | lo
        addr = start + i
        note = ''
        if 0 < val < 10_000_000:
            note = f' <- SMALL INT'
        elif 0x18C * (2**32) <= val <= 0x1A5 * (2**32) + 2**32:
            note = f' <- TIMESTAMP {datetime.utcfromtimestamp(val//1000).strftime("%Y-%m-%d %H:%M")}'
        elif val > 0x700000000000 and val < 0xFFFFFFFFFFFF:
            note = f' <- LARGE'
        if note or (0 < val < 100_000_000):
            print(f'  {hex(addr)}: {val} ({hex(val)}){note}')

kernel32.CloseHandle(hProc)
