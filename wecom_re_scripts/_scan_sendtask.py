import json, sys, re
from collections import Counter
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
path = sys.argv[1]
hits = [json.loads(l) for l in open(path, encoding='utf-8') if l.strip()]
print(f'[*] total hits = {len(hits)}')

pat = re.compile(r'S:\d{10,}_\d{10,}')
appear = {}
for i, h in enumerate(hits):
    for f in h.get('fields', []):
        off = f['off']
        for k in ('cstr', 'w'):
            v = f.get(k)
            if v and pat.search(v):
                appear.setdefault((off, k), []).append((i, pat.search(v).group()))

if not appear:
    print('[!] NO S:xxx_yyy found in any hit')
else:
    print(f'[+] found S: at {len(appear)} (offset, kind):')
    for (off, k), lst in sorted(appear.items()):
        vs = set(x[1] for x in lst)
        print(f'    this+0x{off:02x} ({k})  hits={len(lst)}  vals={vs}')
        i0 = lst[0][0]
        f0 = [ff for ff in hits[i0]['fields'] if ff['off'] == off][0]
        raw_val = f0.get('raw')
        full = f0.get(k)
        print(f'      raw={raw_val}  full={full!r}')

# 更宽的搜索：任何数字长串（可能是 uin）
uin_pat = re.compile(r'\d{15,20}')
uin_pos = {}
for i, h in enumerate(hits):
    for f in h.get('fields', []):
        off = f['off']
        for k in ('cstr', 'w'):
            v = f.get(k)
            if v and uin_pat.search(v):
                uin_pos.setdefault(off, Counter())[uin_pat.search(v).group()] += 1
print()
print(f'[*] any 15-20 digit number (uin-like) offsets = {len(uin_pos)}')
for off, cnt in sorted(uin_pos.items())[:20]:
    top = cnt.most_common(3)
    print(f'    this+0x{off:02x}  {dict(top)}')

# 汇总 this_addr
addrs = Counter(h['this_addr'] for h in hits)
print()
print(f'[*] distinct this pointers = {len(addrs)}')
for a, c in addrs.most_common(10):
    print(f'    {a}  hits={c}')

# 每个 hit 的 offset 0x60..0x80 处的 raw 值（快速表格）
print()
print(f'[*] per-hit snapshot 0x60..0x80:')
print(f'    idx  this            0x60  0x64  0x68  0x6c  0x70  0x74  0x78  0x7c  0x80')
for i, h in enumerate(hits[:20]):
    ff = {f['off']: f.get('raw','?') for f in h['fields']}
    row = '   '.join(ff.get(o, '?')[:10].ljust(10) for o in (0x60,0x64,0x68,0x6c,0x70,0x74,0x78,0x7c,0x80))
    print(f'    {i:3d}  {h["this_addr"][:12]:14s} {row}')
