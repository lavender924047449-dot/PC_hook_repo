# _rank_pb2.py — 修正版 pb 打分，剔除虚高的 length-delimited 越界
# 只信 tags 数 + max_field ≤ 64，用 bytes 但严格 cap 到 128（我们只 dump 了 128B）

import json, sys
from pathlib import Path
from collections import defaultdict

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ndjson = sorted(OUT.glob('callchain_trace_*.ndjson'),
                key=lambda p: p.stat().st_mtime, reverse=True)[0]
print(f'[*] {ndjson.name}')
hits = [json.loads(l) for l in ndjson.read_text(encoding='utf-8').splitlines() if l.strip()]

def clean_pb(pb):
    """把 pb['bytes'] cap 到 128；若 > 128 认为越界，score 减半"""
    tags = pb['tags']; b = pb['bytes']; mf = pb['max_field']
    if mf > 64: return 0        # 明显是垃圾（合理 message field# 一般 <= 32）
    if b > 128: b = 128         # 我们只 dump 了 128B，越界 = 假读
    if tags == 0: return 0
    # 权重：field 数密度 + max_field 合理性
    density = b / max(1, tags)  # 每个 tag 平均字节
    if density > 40: return tags * 30  # 稀疏 = 弱
    return tags * 50 + b

for h in hits:
    n = h['n']; convh = h['conv_hex']
    per_fn_best = defaultdict(lambda: (-1, None, None, 0))
    per_fn_cnt = defaultdict(int)
    for ev in h['events']:
        per_fn_cnt[ev['rva']] += 1
        best = None
        for ai, a in enumerate(ev['args']):
            d = a['d']
            if not d: continue
            s = clean_pb(d['pb'])
            if best is None or s > best[0]:
                best = (s, ai, d)
        if not best or best[0] == 0: continue
        cur = per_fn_best[ev['rva']]
        if best[0] > cur[0]:
            per_fn_best[ev['rva']] = (best[0], ev, best[2], best[1])
    ranked = sorted(per_fn_best.items(), key=lambda kv: kv[1][0], reverse=True)
    print(f'\n=== HIT #{n} (conv={convh[:20]}) top-25 by fixed pb score ===')
    print(f'{"rva":<12} {"d":<2} {"score":<6} {"tags/bytes/mf":<15} {"count":<6} {"a#":<3} hint')
    for rva, (sc, ev, d, ai) in ranked[:25]:
        pb = d['pb']
        cnt = per_fn_cnt[rva]
        hint = ' | '.join(s['s'][:32] for s in d['strs'][:3])
        print(f'0x{rva:08x}  {ev["depth"]:<2} {sc:<6} '
              f'{pb["tags"]:>2}/{min(pb["bytes"],128):>4}/{pb["max_field"]:>3}       '
              f'{cnt:<6} {ai:<3} {hint}')
