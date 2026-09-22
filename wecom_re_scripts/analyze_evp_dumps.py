# analyze_evp_dumps.py — 分析 recv_dump_all.py 产出的 EVP dump
#
# 策略：
#   1. 按头部签名分组统计
#   2. 对 7z 签名 (37 7a bc af 27 1c) 尝试解压
#   3. 对每份原始 + 解压后 buffer 扫 voice 相关 marker
#   4. 输出命中详情

import sys, re, struct, io
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_202247'

MARKERS = [
    b'voice', b'Voice', b'VOICE', b'aeskey', b'silk', b'.silk',
    b'audio', b'amr', b'.amr',
    b'qpic', b'myqcloud', b'wxsnsdy', b'wework', b'.qq.com',
    b'MediaId', b'media_id', b'mediaid', b'FileKey',
    b'\xE8\xAF\xAD\xE9\x9F\xB3',  # 语音 UTF-8
    b'\xe8\xaf\xad',              # 语
    b'\xe9\x9f\xb3',              # 音
    b'FILEASSIST',
    b'http',
]

# 尝试用 py7zr 解压 7z
try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False
    print('[!] py7zr 未安装，7z buffer 只做原始扫描')

files = sorted(OUT_DIR.glob(f'evp_dump_{TS}_seq*.bin'))
print(f'[*] 找到 {len(files)} 份 dump')

# 头部签名统计
sigs = {}
for fp in files:
    data = fp.read_bytes()
    sig = data[:8].hex()
    sigs.setdefault(sig, []).append(fp)

print(f'\n=== 头部签名分组 ({len(sigs)} 种) ===')
for sig, lst in sorted(sigs.items(), key=lambda x: -len(x[1])):
    print(f'  {sig}  ×{len(lst):>3}  例: {lst[0].name}')

def scan(buf, tag):
    hits = []
    for m in MARKERS:
        off = buf.find(m)
        if off >= 0:
            ctx = buf[max(0,off-16):min(len(buf),off+len(m)+64)]
            hits.append({'marker':m, 'off':off,
                         'ctx_hex':ctx.hex()[:200],
                         'ctx_str':bytes(b if 32<=b<127 else 46 for b in ctx).decode('latin-1')[:80]})
    return hits

def try_decompress_7z(data):
    """尝试用 py7zr 解压。若失败则返回 None。"""
    if not HAS_7Z: return None
    try:
        archive = py7zr.SevenZipFile(io.BytesIO(data), mode='r')
        result = archive.readall()
        # result 是 dict 文件名→BytesIO
        out = b''
        for name, bio in result.items():
            out += bio.read()
        return out
    except Exception as e:
        return None

print(f'\n=== 扫描 marker（原始 + 解压后）===\n')

total_hits = 0
for fp in files:
    data = fp.read_bytes()
    hits_raw = scan(data, 'raw')
    decomp = None
    hits_dec = []
    if data.startswith(b'\x37\x7a\xbc\xaf\x27\x1c'):
        decomp = try_decompress_7z(data)
        if decomp:
            hits_dec = scan(decomp, 'decomp')
    total = hits_raw + hits_dec
    if not total: continue
    total_hits += len(total)
    print(f'▼ {fp.name}  raw_size={len(data)}  decomp_size={len(decomp) if decomp else "-"}')
    for h in hits_raw:
        print(f'    [raw]    +0x{h["off"]:04x}  {h["marker"]!r}  → {h["ctx_str"]!r}')
    for h in hits_dec:
        print(f'    [decomp] +0x{h["off"]:04x}  {h["marker"]!r}  → {h["ctx_str"]!r}')
    print()

print(f'[+] 完成，总 marker 命中 = {total_hits}')

# 单独分析 HTTP 响应体（明文）
print(f'\n=== HTTP 响应体明文提取 ===')
for fp in files:
    data = fp.read_bytes()
    if not data.startswith(b'HTTP/1.1'): continue
    # 分离 headers 和 body
    sep = data.find(b'\r\n\r\n')
    if sep < 0: continue
    headers = data[:sep].decode('latin-1', errors='replace')
    body = data[sep+4:]
    print(f'\n▼ {fp.name}  hdrs_len={sep}  body_len={len(body)}')
    for line in headers.split('\r\n')[:8]:
        print(f'    HDR: {line[:120]}')
    # body 前 200 字节 hex + strings
    print(f'    BODY hex[:120] = {body[:60].hex()}')
    body_strs = re.findall(rb'[\x20-\x7e]{6,}', body)
    for s in body_strs[:10]:
        print(f'    BODY str: {s.decode("latin-1")[:100]!r}')
