# decode_all_evp.py — 全量解压 + 逐份扫 voice marker
import sys, lzma, re
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_202247'
files = sorted(OUT_DIR.glob(f'evp_dump_{TS}_seq*.bin'))

MARKERS = [
    b'voice', b'Voice', b'silk', b'aeskey', b'aes_key',
    b'audio', b'amr',
    b'qpic', b'myqcloud', b'wxsnsdy', b'wework.qpic',
    b'MediaId', b'media_id', b'FileKey',
    b'\xe8\xaf\xad\xe9\x9f\xb3',
    b'\xe8\xaf\xad',
    b'\xe9\x9f\xb3',
    b'FILEASSIST',
    b'CIGAEBD',   # 之前样本里 msg_id 前缀
]

DECOMP_DIR = OUT_DIR / f'decompressed_{TS}'
DECOMP_DIR.mkdir(exist_ok=True)

def decomp(data):
    if not data.startswith(b'\x37\x7a\xbc\xaf\x27\x1c'):
        return None
    pkg = data[32:]
    try:
        dec = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{'id':lzma.FILTER_LZMA2,'preset':lzma.PRESET_DEFAULT}])
        return dec.decompress(pkg)
    except Exception:
        return None

def scan(buf):
    hits = []
    for m in MARKERS:
        off = buf.find(m)
        if off >= 0:
            ctx = buf[max(0,off-16):min(len(buf),off+len(m)+80)]
            hits.append({
                'marker': m,
                'off': off,
                'ctx_str': bytes(b if 32<=b<127 else 46 for b in ctx).decode('latin-1'),
                'ctx_hex': ctx.hex()[:200],
            })
    return hits

def strings(buf, minlen=6):
    return [(m.start(), m.group().decode('latin-1', errors='replace'))
            for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, buf)]

n_decomp = 0
n_hit = 0
by_size = {}
for fp in files:
    data = fp.read_bytes()
    d = decomp(data)
    if d is None: continue
    n_decomp += 1
    outp = DECOMP_DIR / (fp.stem + '_decomp.bin')
    outp.write_bytes(d)
    h = scan(d)
    if not h: 
        by_size.setdefault('no_hit', []).append((fp.name, len(d)))
        continue
    n_hit += 1
    print(f'\n★★★ {fp.name}  raw={len(data)}  decomp={len(d)}')
    for hit in h:
        print(f'    +0x{hit["off"]:04x}  {hit["marker"]!r}')
        print(f'      ctx: {hit["ctx_str"][:120]!r}')

print(f'\n[+] decompressed {n_decomp}/71  |  voice-marker hit = {n_hit}')

# 打印所有 decompressed 的顶层 strings 概览
print(f'\n=== 各 decomp 的显著 ASCII strings (每份最多 8 条) ===\n')
for fp in files:
    data = fp.read_bytes()
    d = decomp(data)
    if d is None: continue
    strs = strings(d, minlen=8)
    if not strs: continue
    # 只显示前 8 条不重复的
    seen = set()
    top = []
    for off, s in strs:
        if s in seen: continue
        seen.add(s)
        top.append((off, s))
        if len(top) >= 8: break
    print(f'▼ {fp.name}  decomp={len(d)}')
    for off, s in top:
        print(f'    +0x{off:04x}  {s[:110]!r}')
    print()
