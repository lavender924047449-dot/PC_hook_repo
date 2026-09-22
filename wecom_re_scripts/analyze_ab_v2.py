# analyze_ab_v2.py — 在 fwd_ab_v2 结果里，按 handler 分组，找 A vs B 变化的 meta u32 offset
import json, struct
from pathlib import Path
from collections import defaultdict, Counter

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
target = sorted(OUT.glob('fwd_ab_v2_*.json'))[-1]
print(f'[+] {target.name}')
data = json.loads(target.read_text(encoding='utf-8'))
events = data['events']
print(f'events: {len(events)}\n')

def u32(b, o):
    return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

# group by (phase, handler)
groups = defaultdict(list)
for e in events:
    groups[(e['phase'], e['handlerPtr'])].append(e)

for k, evs in sorted(groups.items()):
    print(f'  Phase{k[0]} handler={k[1]}: {len(evs)} events')

# 每个 handler，取 A/B 各若干条 meta，对比同 offset 的 u32 分布
print('\n' + '='*70)
print('每 handler 下 meta u32 字段 A vs B 差异分析')
print('='*70)

handlers = set(e['handlerPtr'] for e in events)

interesting_offsets = defaultdict(list)  # offset -> [(handler, A_vals, B_vals)]

for h in sorted(handlers):
    A = [e for e in events if e['phase'] == 2 and e['handlerPtr'] == h]
    B = [e for e in events if e['phase'] == 3 and e['handlerPtr'] == h]
    if not A or not B:
        continue
    # 取所有 meta 都是 bytes；每个 offset 汇集 A/B 值
    Al = [bytes(e['meta']) for e in A if e.get('meta')]
    Bl = [bytes(e['meta']) for e in B if e.get('meta')]
    if not Al or not Bl:
        continue
    Lmin = min(min(len(x) for x in Al), min(len(x) for x in Bl))
    print(f'\n--- handler={h}  (A={len(Al)}, B={len(Bl)}, meta_len_min={Lmin}) ---')

    # 逐 4字节 offset
    diff_offsets = []
    for off in range(0, Lmin - 4, 4):
        aset = set(u32(x, off) for x in Al)
        bset = set(u32(x, off) for x in Bl)
        if not (aset & bset) and aset and bset:
            # A/B 完全不同 → 强候选
            diff_offsets.append((off, aset, bset, 'DISJOINT'))
        elif aset != bset and len(aset | bset) > 1:
            diff_offsets.append((off, aset, bset, 'DIFFER'))

    # 打印 top disjoint（更有意义）
    disjoint = [d for d in diff_offsets if d[3] == 'DISJOINT']
    print(f'  DISJOINT offsets: {len(disjoint)}')
    for off, aset, bset, _ in disjoint[:30]:
        av = list(aset)[:3]
        bv = list(bset)[:3]
        # 排除全 0
        if aset == {0} and bset == {0}: continue
        av_hex = [f'0x{v:08x}' for v in av]
        bv_hex = [f'0x{v:08x}' for v in bv]
        print(f'    off=+{off:03d}: A={av_hex}  B={bv_hex}')
        interesting_offsets[off].append((h, aset, bset))

# 汇总：跨 handler 均为 disjoint 的 offset（最强候选）
print('\n' + '='*70)
print('跨 handler 稳定 disjoint 的 offset（最强 dest_conv 候选）:')
print('='*70)
for off, lst in sorted(interesting_offsets.items()):
    if len(lst) >= 2:  # 至少 2 个 handler 都在此 offset 上分歧
        print(f'\n  off=+{off}:')
        for h, aset, bset in lst:
            av = [f'0x{v:08x}' for v in list(aset)[:2]]
            bv = [f'0x{v:08x}' for v in list(bset)[:2]]
            print(f'    handler={h}  A={av}  B={bv}')

# 同样对 task 字段做 diff
print('\n' + '='*70)
print('task[0:112] 中 A vs B disjoint 的 offset')
print('='*70)
for h in sorted(handlers):
    A = [bytes(e['task']) for e in events if e['phase']==2 and e['handlerPtr']==h and e.get('task')]
    B = [bytes(e['task']) for e in events if e['phase']==3 and e['handlerPtr']==h and e.get('task')]
    if not A or not B: continue
    Lmin = min(min(len(x) for x in A), min(len(x) for x in B))
    ds = []
    for off in range(0, Lmin - 4, 4):
        aset = set(u32(x, off) for x in A)
        bset = set(u32(x, off) for x in B)
        if not (aset & bset) and aset and bset:
            if aset == {0} and bset == {0}: continue
            ds.append((off, aset, bset))
    print(f'\n  handler={h}: task DISJOINT offsets = {len(ds)}')
    for off, aset, bset in ds[:20]:
        av = [f'0x{v:08x}' for v in list(aset)[:2]]
        bv = [f'0x{v:08x}' for v in list(bset)[:2]]
        print(f'    task+{off:03d}: A={av}  B={bv}')

# 保存到文件
ts = target.stem.replace('fwd_ab_v2_', '')
out = OUT / f'ab_v2_analysis_{ts}.json'
out.write_text(json.dumps({
    'source': target.name,
    'handlers': list(handlers),
    'meta_disjoint_by_offset': {
        str(off): [{'handler': h, 'A': [f'0x{v:08x}' for v in aset], 'B': [f'0x{v:08x}' for v in bset]}
                   for h, aset, bset in lst]
        for off, lst in interesting_offsets.items() if len(lst) >= 2
    },
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] {out}')
