# _rank_pb.py — 从 callchain_trace_*.ndjson 里排出 ConstructMessageProtobuf 最像的 fn
#
# 排序策略（关键）：
#   score = pb_tags * 100 + pb_bytes（越大越像 proto builder）
#   仅取每个 (rva) 在整段 trace 内**最大** score（因为同一 rva 可能被循环内调用 N 次）
#   显示 top 30 fn + 该 fn 在这次 HIT 内被调用的次数
#
# 用法：python _rank_pb.py
# 自动挑最新 ndjson。

import json, sys
from pathlib import Path
from collections import defaultdict

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ndjson = sorted(OUT.glob('callchain_trace_*.ndjson'),
                key=lambda p: p.stat().st_mtime, reverse=True)
if not ndjson:
    print('no trace ndjson'); sys.exit(1)
path = ndjson[0]
print(f'[*] using {path.name}')

hits = [json.loads(l) for l in path.read_text(encoding='utf-8').splitlines() if l.strip()]
print(f'[*] {len(hits)} PreSend HITs')

for h in hits:
    n = h['n']; convh = h['conv_hex']
    per_fn_best = defaultdict(lambda: (-1, None, 0))   # rva -> (score, ev, count)
    per_fn_cnt = defaultdict(int)
    for ev in h['events']:
        per_fn_cnt[ev['rva']] += 1
        # 挑 4 args 里 pb tags 最大的
        best_pb = None; best_arg_idx = -1
        for ai, a in enumerate(ev['args']):
            d = a['d']
            if not d: continue
            pb = d['pb']; score = pb['tags'] * 100 + pb['bytes']
            if best_pb is None or score > best_pb[0]:
                best_pb = (score, pb, d, ai)
        if best_pb is None: continue
        score = best_pb[0]
        cur = per_fn_best[ev['rva']]
        if score > cur[0]:
            per_fn_best[ev['rva']] = (score, ev, best_pb)

    ranked = sorted(per_fn_best.items(), key=lambda kv: kv[1][0], reverse=True)
    print(f'\n=== PreSend HIT #{n} (conv={convh[:20]}) top-30 by pb score ===')
    print(f'{"rva":<12} {"depth":<5} {"pb(tags/bytes/maxF)":<22} {"count":<6} {"arg#":<4} {"hint"}')
    for rva, (score, ev, best) in ranked[:30]:
        pb = best[1]; d = best[2]; ai = best[3]
        cnt = per_fn_cnt[rva]
        hint = ','.join(s['s'][:24] for s in d['strs'][:2])
        print(f'0x{rva:08x}  {ev["depth"]:<5} '
              f'{pb["tags"]:>2}/{pb["bytes"]:>4}/{pb["max_field"]:>3}         {cnt:<6} {ai:<4} {hint}')

    # 额外：找带 FILEASSIST sentinel 的 fn（说明拿到了 MessageObject）
    print(f'\n=== HIT #{n} FILEASSIST-carrying calls (top 15) ===')
    sen_fns = defaultdict(list)
    for ev in h['events']:
        for ai, a in enumerate(ev['args']):
            d = a['d']
            if not d: continue
            hex_str = d['hex'].lower()
            # "FILEASSIST" 的 hex 是 46494c45415353495354
            if '46494c45415353495354' in hex_str:
                sen_fns[ev['rva']].append((ev['seq'], ai))
                break
    for rva, occ in sorted(sen_fns.items(), key=lambda kv: len(kv[1]), reverse=True)[:15]:
        depth = next((e['depth'] for e in h['events'] if e['rva']==rva), '?')
        print(f'  0x{rva:08x}  depth={depth}  hit_seqs={[o[0] for o in occ[:8]]}...  (total {len(occ)})')
