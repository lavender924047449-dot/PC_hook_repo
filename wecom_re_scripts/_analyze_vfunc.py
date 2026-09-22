# _analyze_vfunc.py — 分析 hook_vfunc_*.ndjson 的所有 hit
# 1. vtable 反查 76 条 entry pool
# 2. this dump 前 32 字节 hex + 全 ASCII runs
# 3. 找 msg id / conv id / 文件路径 / uin 等特征字符串
import json, re, sys
from pathlib import Path

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ndjson = sorted(OUT.glob('hook_vfunc_*.ndjson'),
                key=lambda p: p.stat().st_mtime, reverse=True)[0]
pool = sorted(OUT.glob('parse_typeurl_pool_*.json'),
              key=lambda p: p.stat().st_mtime, reverse=True)[0]
print(f'[*] ndjson: {ndjson.name}')
print(f'[*] pool:   {pool.name}')

# 建 vtable→type 表
p = json.loads(pool.read_text(encoding='utf-8'))
fn2type = {}
for e in p['entries']:
    for d in e['dwords']:
        if 0x400000 <= d < 0x0c000000:
            fn2type.setdefault(d, []).append((e['idx'], e['type_url']))

hits = [json.loads(l) for l in ndjson.read_text(encoding='utf-8').splitlines() if l.strip()]
print(f'[*] {len(hits)} hits total')

# 按 SER hits 展开（BYT this 一样）
sers = [h for h in hits if h['tag']=='SER']
byts = [h for h in hits if h['tag']=='BYT']
print(f'    SER: {len(sers)}   BYT: {len(byts)}')

def ascii_runs(hex_str, minlen=4):
    raw = bytes.fromhex(hex_str)
    out=[]; run=b''
    for b in raw:
        if 32<=b<127: run += bytes([b])
        else:
            if len(run)>=minlen: out.append(run.decode('ascii','replace'))
            run=b''
    if len(run)>=minlen: out.append(run.decode('ascii','replace'))
    return out

# 按 vtable 分组
by_vt = {}
for h in sers:
    vt = int(h['vtable'], 16)
    by_vt.setdefault(vt, []).append(h)

print(f'\n=== SER hits grouped by vtable ({len(by_vt)} unique vtables) ===')
for vt, hs in sorted(by_vt.items(), key=lambda kv: -len(kv[1])):
    types = fn2type.get(vt, [])
    tstr = ','.join(f'#{t[0]}:{t[1]}' for t in types[:2]) if types else '(not in pool)'
    print(f'\nvtable=0x{vt:08x}  n_hits={len(hs)}  {tstr}')
    # 前 3 个 hit 的字符串
    for h in hs[:3]:
        runs = ascii_runs(h['this_hex'])
        top = [r for r in runs if len(r)>=6][:5]
        arg0_runs = []
        # 若 SER，看 ndjson 里是否有 arg0
        print(f'  #{h["n"]:03d} this={h["this_addr"]}  strs={top}')

# 尝试从 arg0（CodedOutputStream*）看它内部 buffer
# CodedOutputStream 典型布局：EpsCopyOutputStream stream_; ... 具体太复杂
# 简单看：arg0 前 128B hex 前 8 字节可能是内部指针
print(f'\n=== SER arg0 (CodedOutputStream*) previews ===')
for h in sers[:6]:
    # arg0 dump 单独存了文件；ndjson 里也有
    a0 = h.get('arg0')
    if not a0: continue
    hx = a0['hex']
    raw = bytes.fromhex(hx)
    runs = ascii_runs(hx)
    top = [r for r in runs if len(r)>=6][:6]
    print(f'  #{h["n"]:03d} arg0={a0["addr"]}  first16={raw[:16].hex()}  strs={top}')
