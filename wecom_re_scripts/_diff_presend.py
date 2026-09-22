"""离线分析 hook_presend_deep 3 次 HIT，做 A/B/C diff。"""
import sys, json, re
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
D = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_114043'

def find_all(data, pat):
    out = []; i = 0
    while True:
        j = data.find(pat, i)
        if j < 0: break
        out.append(j); i = j + 1
        if len(out) > 20: break
    return out

ndjson = D / f'hook_presend_deep_{TS}.ndjson'
hits = [json.loads(l) for l in ndjson.open(encoding='utf-8')]
print(f'[+] {len(hits)} HITs')

for h in hits:
    print(f'\n=== HIT #{h["n"]} ===  esp={h["esp"]}')
    for ai in ['0','1','2','3']:
        a = h['args'].get(ai)
        if a: print(f'  args[{ai}] addr={a["addr"]}  L2 ptrs={len(a.get("l2",[]))}')

patterns = [b'FILEASSIST', b'S:1688', b'1688855', b'7881300', b'7881299', b'S:788',
            b'R:', b'WM:', b'msgtype', b'text', b'appinfo', b'file', b'voice',
            b'silk', b'image', b'video', b'.silk', b'.amr', b'.jpg', b'.txt',
            b'content', b'body', b'json', b'wework', b'protocol']

all_bins = sorted(D.glob(f'hook_presend_deep_{TS}_h*.bin'))
print(f'\n[+] 全 bin 扫 CID/关键词 ({len(all_bins)} bins)\n')

by_hit = {'1':[], '2':[], '3':[]}
for bp in all_bins:
    data = bp.read_bytes()
    m = re.match(r'.*_h(\d+)_a(\d+)(?:_l2_(\d+)_(0x[0-9a-f]+))?\.bin', bp.name)
    if not m: continue
    hn, ai, li, laddr = m.groups()
    finds = []
    for pat in patterns:
        pos = find_all(data, pat)
        if pos:
            finds.append((pat.decode('utf-8', 'replace'), pos))
    if finds:
        label = f'a{ai}' + (f'_L2[{li}]@{laddr}' if li else '')
        by_hit.setdefault(hn, []).append((label, finds, bp.name))

for hn in ['1','2','3']:
    print(f'━━━ HIT #{hn} ━━━')
    if not by_hit[hn]:
        print(f'  (无匹配)\n')
        continue
    for label, finds, fname in by_hit[hn]:
        for pat, pos in finds:
            print(f'  {label:32s} {pat!r:16s} @ offsets {[hex(p) for p in pos[:5]]}')
    print()

# 3 次 HIT 的 args[1] 前 2KB ASCII runs 对比
def ascii_runs(data, min_len=8, max_bytes=None):
    runs = []; run = ''; st = 0
    for i, b in enumerate(data[:max_bytes or len(data)]):
        if 0x20 <= b <= 0x7E:
            if not run: st = i
            run += chr(b)
        else:
            if len(run) >= min_len: runs.append((st, run))
            run = ''
    if len(run) >= min_len: runs.append((st, run))
    return runs

print('\n' + '='*70)
print('[+] 3 次 HIT args[1] 前 2KB ASCII runs 对比 (min 8 chars)')
for hn in ['1','2','3']:
    print(f'\n─── HIT #{hn} args[1] ────')
    bp = D / f'hook_presend_deep_{TS}_h{hn}_a1.bin'
    if bp.exists():
        for off, s in ascii_runs(bp.read_bytes(), 8):
            print(f'  @0x{off:04x}: {s[:100]!r}')

# HIT #2 args[1] L2[10] 有 text 字符串 — 深挖
print('\n' + '='*70)
print('[+] HIT #2 args[1] L2[10] 深挖 (text 出现处):')
for bp in D.glob(f'hook_presend_deep_{TS}_h2_a1_l2_10_*.bin'):
    print(f'  file: {bp.name}')
    data = bp.read_bytes()
    for off, s in ascii_runs(data, 4):
        marker = ' ★' if any(k in s for k in ['text','file','voice','silk','FILEASSIST','1688','7881']) else ''
        print(f'    @0x{off:04x}: {s[:120]!r}{marker}')
