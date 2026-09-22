"""离线扫本轮 cgi_hunt_20260914_110718* 产物，找 CID 位置和 proto 边界。"""
import sys, json
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

D = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_110718'

# 1. arena 全扫
arena_p = D / f'cgi_hunt_{TS}_h1_arena.bin'
arena = arena_p.read_bytes()
print(f'[+] Arena {arena_p.name} size={len(arena)/1024:.1f}KB\n')

# 各种可能的 CID 形式
patterns = [
    (b'1688855', 'self_uin_ascii'),
    (b'S:1688', 'S_prefix'),
    (b'FILEASSIST', 'FTA'),
    (b'7881300', 'contact_uin_prefix'),
    (b'\x00\x00\x00\x00S:', 'S_prefix_after_zeros'),
    # UTF-16 LE
    (b'1\x006\x008\x008\x008\x005\x005\x00', 'self_uin_utf16le'),
    # varint 1688855042791155 = big number
]
for pat, name in patterns:
    idx = 0; hits = []
    while True:
        i = arena.find(pat, idx)
        if i < 0: break
        hits.append(i); idx = i + 1
        if len(hits) > 50: break
    print(f'  {name!r:25s} hits={len(hits)}  first@{hex(hits[0]) if hits else "-"}')

# 2. 每个候选 bin 扫 CID
print(f'\n[+] Candidate bins:')
cids_found = []
for bp in sorted(D.glob(f'cgi_hunt_{TS}_h1_c*.bin'), key=lambda p: int(p.stem.rsplit('_c',1)[1])):
    data = bp.read_bytes()
    idx1 = data.find(b'1688855')
    idxS = data.find(b'S:1688')
    idxFTA = data.find(b'FILEASSIST')
    if idx1 >= 0 or idxS >= 0 or idxFTA >= 0:
        print(f'  {bp.name}: 1688855@{hex(idx1) if idx1>=0 else "-"}  S:1688@{hex(idxS) if idxS>=0 else "-"}  FTA@{hex(idxFTA) if idxFTA>=0 else "-"}')
        cids_found.append(bp.name)

if not cids_found:
    print(f'  (0 candidate bins contain any CID marker)')

# 3. 检查 ndjson 里的 args[3] arena base 是否稳定
print(f'\n[+] ndjson HITs:')
nd = D / f'cgi_hunt_{TS}.ndjson'
if nd.exists():
    for line in nd.open(encoding='utf-8'):
        h = json.loads(line)
        print(f'  HIT #{h["n"]} N={h["N"]} args={h["args"]}')
else:
    print(f'  (ndjson not found)')

# 4. 前几个 KB 的十六进制 dump（看 arena 头部结构）
print(f'\n[+] Arena[0..256] hex:')
print(' '.join(f'{b:02x}' for b in arena[:256]))
print(f'\n[+] Arena[256..512] hex:')
print(' '.join(f'{b:02x}' for b in arena[256:512]))
