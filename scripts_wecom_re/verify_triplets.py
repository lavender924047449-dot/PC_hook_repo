"""
验证扫描结果：读取命中地址周边的内存以找 message_id
重点看 0x266689b8 (today's ts) 和 0x2752xxxx (cluster) 区域
"""
import ctypes, ctypes.wintypes, struct, json, pathlib
from datetime import datetime

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\verify_triplets.json')

kernel32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

hProc = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, PID)

def read_mem(addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    if ok and n.value > 0:
        return buf.raw[:n.value]
    return None

def hexdump(data, base_addr=0, row=16):
    lines = []
    for i in range(0, len(data), row):
        chunk = data[i:i+row]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  {base_addr+i:08x}  {hex_part:<{row*3-1}}  {asc_part}')
    return '\n'.join(lines)

# Key addresses to examine
TARGETS = [
    (0x266689b8, "seq=1, today 2026-09-09 13:11"),
    (0xfb19ee8, "seq=1, today 2026-09-09 11:39"),
    (0x2659ddd8, "seq=11498, 2023-11-24"),
    (0x2659e408, "seq=50360, 2026-03-18"),
    (0x2659e828, "seq=233183, 2026-05-07"),
    (0x2752d2d8, "cluster seq=1038, 2024-01-12"),
    (0x2752d49c, "cluster seq=68, 2024-12-25"),
    (0x2752d75c, "cluster seq=1430, 2026-06-25"),
    (0x260aca40, "same seq=336 x4, 2024-04-21"),
]

results = {}
for addr, label in TARGETS:
    # Read 256 bytes starting 64 bytes before the hit (to see message_id before seq)
    read_addr = addr - 64
    data = read_mem(read_addr, 256)
    if data:
        results[hex(addr)] = {
            'label': label,
            'hex': hexdump(data, read_addr),
            'raw_ints': []
        }
        # Parse as int64 pairs (8 bytes each)
        for j in range(0, len(data)-8, 8):
            lo, hi = struct.unpack_from('<II', data, j)
            val = (hi << 32) | lo
            if val > 0:
                results[hex(addr)]['raw_ints'].append({'off': j-64, 'val': val, 'hex': hex(val)})
        
        print(f"\n=== {label} @ {hex(addr)} ===")
        print(results[hex(addr)]['hex'][:800])
    else:
        print(f"\n=== {label} @ {hex(addr)} === FAILED TO READ")

kernel32.CloseHandle(hProc)
OUT.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\nSaved to {OUT}')
