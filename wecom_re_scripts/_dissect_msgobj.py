# _dissect_msgobj.py — 剖析 MessageObject 3KB dump
# 找 msgtype 字段 + 相关小 int + std::string / proto ptr
import struct, re
from pathlib import Path

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
fp = OUT_DIR / 'msgobj_probe_20260914_142108_n1.bin'
data = fp.read_bytes()
print(f'MessageObject dump: {fp.name}, size={len(data)}')

# 1. vtable (offset 0)
vt = struct.unpack('<I', data[:4])[0]
print(f'\n★ vtable @+0 = 0x{vt:08x}  (.rdata polymorphic class)')

# 2. 全部 uint32 字段扫描
print(f'\n── 全 uint32 字段扫描 (前 512B) ──')
print(f'{"off":>6} {"value":>12} {"hex":>10} {"note"}')
for off in range(0, min(512, len(data)), 4):
    v = struct.unpack('<I', data[off:off+4])[0]
    note = ''
    if 1 <= v <= 300 and v != 0:
        note = '← 小 int (msgtype/bool/enum/count 候选)'
    elif 0x400000 <= v <= 0x0c000000:
        note = '← .text/.rdata (fn ptr / vtable)'
    elif 0x14000000 <= v <= 0x40000000:
        note = '← heap (nested obj)'
    elif v == 0:
        note = ''
    else:
        note = ''
    if note:
        print(f'  +{off:04x}  {v:>12}  0x{v:08x}  {note}')

# 3. 找 std::string SSO 模式 (MSVC: capacity/size + 内联/heap ptr)
print(f'\n── std::string SSO / 长字符串 候选 ──')
# MSVC std::string 布局: [16B 内联 buffer or ptr][size 4B][cap 4B]
# 短字符串: 内联 buffer 有内容, size < 16, cap == 15
# 长字符串: ptr @ +0..+3 指向 heap，size 大，cap 大
for off in range(0, min(1024, len(data) - 24), 4):
    # 尝试判定长字符串: [+0] = heap ptr, [+16] = size (0 < size < 4096), [+20] = cap (>= size)
    ptr = struct.unpack('<I', data[off:off+4])[0]
    if 0x14000000 <= ptr <= 0x40000000:
        try:
            size = struct.unpack('<I', data[off+16:off+20])[0]
            cap = struct.unpack('<I', data[off+20:off+24])[0]
            if 0 < size < 4096 and cap >= size and cap < 65536:
                print(f'  +{off:04x}  ptr=0x{ptr:08x}  size={size}  cap={cap}  ★可能 std::string(长)')
        except: pass
    # SSO 短字符串: bytes[+0..+15] 是 ASCII, [+16] = size < 16, [+20] = 15
    else:
        buf = data[off:off+16]
        if all(0x20 <= b < 0x7f or b == 0 for b in buf):
            try:
                size = struct.unpack('<I', data[off+16:off+20])[0]
                cap = struct.unpack('<I', data[off+20:off+24])[0]
                if 0 < size < 16 and cap == 15:
                    txt = buf[:size].decode('latin-1', errors='replace')
                    print(f'  +{off:04x}  SSO {txt!r:<20}  size={size}')
            except: pass

# 4. ASCII 字符串
print(f'\n── 直接 ASCII 字符串 (≥4 字符) ──')
for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
    print(f'  @+{m.start():04x}  {m.group().decode("latin-1"):.150}')

# 5. 数据完整 hex dump（前 512B）
print(f'\n── header 前 512B hex ──')
for i in range(0, min(512, len(data)), 16):
    chunk = data[i:i+16]
    hexs = ' '.join(f'{b:02x}' for b in chunk)
    ascs = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
    print(f'  +{i:04x}  {hexs:<48}  {ascs}')
