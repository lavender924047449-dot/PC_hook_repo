"""
提取完整三元组：从 ctypes 扫描结果确认 (message_id, seq, ts) 结构
在命中地址前 8 字节读取 message_id，并进一步验证
"""
import ctypes, ctypes.wintypes, struct, json, pathlib
from datetime import datetime

PID = 20632
OUT_JSON = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\confirmed_triplets.json')

kernel32 = ctypes.windll.kernel32
hProc = kernel32.OpenProcess(0x0010 | 0x0400, False, PID)

def read_mem(addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value] if ok and n.value > 0 else None

# 已知命中地址（来自 ctypes_scan.py）
HITS = [
    0x266689b8,  # seq=1, today 13:19
    0xfb19ee8,   # seq=1, today 11:39
    0x2659ddd8,  # seq=11498, 2023-11-24
    0x2659e408,  # seq=50360, 2026-03-18
    0x2659e828,  # seq=233183, 2026-05-07
    0x2752d2d8,  # cluster 2024-01-12
    0x2752d49c,  # cluster 2024-12-25
    0x2752d75c,  # cluster 2026-06-25
    0x260aca40,  # same-seq cluster 2024-04-21
    0x2797fe54,  # seq=783, 2026-08-14
]

triplets = []

for hit in HITS:
    # 读取 hit 地址前 16 字节和后 32 字节，共 48 字节
    data = read_mem(hit - 16, 64)
    if not data:
        print(f'  {hex(hit)}: READ FAILED')
        continue
    
    # offset 16 = hit 地址
    seq_lo, seq_hi = struct.unpack_from('<II', data, 16)
    st_lo, st_hi   = struct.unpack_from('<II', data, 24)
    
    seq = (seq_hi << 32) | seq_lo
    ts_ms = (st_hi << 32) | st_lo
    ts_s  = ts_ms // 1000 if ts_ms > 0 else 0
    
    # 8 字节前 = 候选 message_id
    mid_lo, mid_hi = struct.unpack_from('<II', data, 8)
    message_id = (mid_hi << 32) | mid_lo
    
    # 16 字节前
    prev_lo, prev_hi = struct.unpack_from('<II', data, 0)
    prev_val = (prev_hi << 32) | prev_lo
    
    # 验证: seq > 0, ts_s 在 2020-2030 范围
    valid = (0 < seq <= 10_000_000 and 1577836800 < ts_s < 1893456000)
    
    try:
        dt = datetime.utcfromtimestamp(ts_s).strftime('%Y-%m-%d %H:%M')
    except:
        dt = 'invalid'
    
    t = {
        'addr': hex(hit),
        'message_id': message_id,
        'message_id_hex': hex(message_id),
        'prev_val': prev_val,
        'sequence': seq,
        'send_time_ms': ts_ms,
        'send_time_s': ts_s,
        'send_time_dt': dt,
        'valid': valid
    }
    triplets.append(t)
    
    status = '✓' if valid else '✗'
    print(f'{status} addr={hex(hit)}')
    print(f'   message_id={message_id}({hex(message_id)}) seq={seq} ts_s={ts_s}({dt} UTC)')
    print(f'   prev_val={prev_val}({hex(prev_val)})')

kernel32.CloseHandle(hProc)

# 过滤有效三元组
valid_triplets = [t for t in triplets if t['valid']]
print(f'\n=== 有效三元组 ({len(valid_triplets)} 个) ===')
for t in valid_triplets:
    print(f'  message_id={t["message_id"]} seq={t["sequence"]} ts={t["send_time_dt"]} UTC')

OUT_JSON.write_text(json.dumps({
    'count': len(valid_triplets),
    'triplets': valid_triplets,
    'all': triplets
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\nSaved to {OUT_JSON}')
