# try_decompress.py — 尝试用各种方式解压 EVP dump 里的 7z-header 数据
import sys, lzma, struct
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_202247'
files = sorted(OUT_DIR.glob(f'evp_dump_{TS}_seq*.bin'))

# 挑几份 7z-magic 的样本试
targets = []
for fp in files:
    d = fp.read_bytes()
    if d.startswith(b'\x37\x7a\xbc\xaf\x27\x1c'):
        targets.append((fp, d))

print(f'[*] {len(targets)} 份 7z-magic 数据待测')

def try_all(data, tag):
    tried = []
    # 1) 直接 lzma FORMAT_XZ / ALONE / RAW（各种）
    for fmt_name, fmt in [
        ('XZ', lzma.FORMAT_XZ),
        ('ALONE', lzma.FORMAT_ALONE),
        ('AUTO', lzma.FORMAT_AUTO),
    ]:
        try:
            r = lzma.decompress(data, format=fmt)
            tried.append((f'lzma-{fmt_name}-raw', len(r), r[:80]))
        except Exception as e:
            tried.append((f'lzma-{fmt_name}-raw', 'FAIL', str(e)[:60]))
    # 2) 跳过 7z header 尝试
    # 标准 7z:
    #   0..5   : signature 37 7a bc af 27 1c
    #   6..7   : version 00 04
    #   8..11  : start-header CRC
    #   12..19 : nextHeaderOffset (u64 LE)
    #   20..27 : nextHeaderSize   (u64 LE)
    #   28..31 : nextHeaderCRC
    if len(data) >= 32:
        nh_off = struct.unpack('<Q', data[12:20])[0]
        nh_size = struct.unpack('<Q', data[20:28])[0]
        # packed streams 起始位置 = 32
        tried.append(('7z-header', f'nh_off={nh_off} nh_size={nh_size}', ''))
        pkg = data[32:]
        for fmt_name, fmt in [('XZ',lzma.FORMAT_XZ),('ALONE',lzma.FORMAT_ALONE),('RAW-LZMA2-default',None)]:
            try:
                if fmt_name.startswith('RAW'):
                    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                        filters=[{'id':lzma.FILTER_LZMA2,'preset':lzma.PRESET_DEFAULT}])
                    r = dec.decompress(pkg)
                else:
                    r = lzma.decompress(pkg, format=fmt)
                tried.append((f'lzma-{fmt_name}-skip32', len(r), r[:80]))
            except Exception as e:
                tried.append((f'lzma-{fmt_name}-skip32', 'FAIL', str(e)[:60]))
    return tried

# 只试前 3 份代表
for fp, data in targets[:3]:
    print(f'\n▼ {fp.name}  size={len(data)}')
    print(f'  head32 hex: {data[:32].hex()}')
    for method, res, extra in try_all(data, fp.name):
        if isinstance(res, int):
            print(f'  ✓ {method:>28s}  → {res} bytes  head={extra.hex() if isinstance(extra, bytes) else extra}')
        else:
            print(f'  ✗ {method:>28s}  {res}  {extra}')
