# _find_silk_ctx.py — 精确定位 .silk / file_id / duration / magiccube / aeskey 的字节上下文
import re
from pathlib import Path
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_141437'

TARGETS = [
    (b'.silk', 128),
    (b'silk',   64),
    (b'file_id', 128),
    (b'duration', 96),
    (b'aeskey', 128),
    (b'magiccube', 200),
    (b'rtxapp', 200),
    (b'MediaCdnKeyInfo', 200),
    (b'voice_length', 64),
    (b'file_size', 64),
    (b'audio', 64),
    (b'amr', 32),
    (b'\x00\x08\x01', 32),  # proto wire tag 0x08 (field 1, varint) preceded by zero — msg_type=1?
]

files = sorted(OUT_DIR.glob(f'voice_recv_{TS}_*.bin'))
print(f'扫描 {len(files)} 个 dump\n')

for fp in files:
    data = fp.read_bytes()
    for needle, ctx_bytes in TARGETS:
        p = 0
        found_any = False
        while True:
            p = data.find(needle, p)
            if p < 0: break
            if not found_any:
                print(f'{"="*76}\n▶ {fp.name}   needle={needle!r}')
                found_any = True
            lo = max(0, p - 20)
            hi = min(len(data), p + len(needle) + ctx_bytes)
            chunk = data[lo:hi]
            hexs = chunk.hex()
            ascs = ''.join(chr(b) if 0x20<=b<0x7f else '.' for b in chunk)
            print(f'   @+{p:#06x}  hex={hexs[:250]}')
            print(f'              asc={ascs[:120]}')
            p += 1
print('\n[done]')
