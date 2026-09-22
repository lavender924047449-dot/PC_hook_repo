# _path_to.py — 从 PreSend 到目标 RVA 的最短静态调用路径（BFS in callchain graph）
import json, sys
from pathlib import Path
from collections import deque

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
CHAIN = sorted([p for p in OUT.glob('callchain_*.json')
                if 'trace' not in p.name and 'flat' not in p.name],
               key=lambda p: p.stat().st_mtime, reverse=True)[0]
J = json.loads(CHAIN.read_text(encoding='utf-8'))
IB = J['meta']['image_base']
G = {fn['va']: [c['tgt_va'] for c in fn['calls']] for fn in J['functions']}
DEPTH = {fn['va']: fn['depth'] for fn in J['functions']}
presend_va = J['meta']['presend_va']

# 目标 RVA 列表（可从命令行传，或用默认）
if len(sys.argv) > 1:
    targets_rva = [int(x, 16) for x in sys.argv[1:]]
else:
    targets_rva = [0x09926c00, 0x09bc1db8, 0x09ba5b3d, 0x09ba6060,
                   0x09ba54f0, 0x09bc1d97, 0x09bc1da2, 0x001e9427,
                   0x09bc1ea4, 0x09ba5538]

for trva in targets_rva:
    tva = trva + IB
    # BFS from presend
    par = {presend_va: None}
    q = deque([presend_va])
    found = False
    while q:
        u = q.popleft()
        if u == tva: found = True; break
        for v in G.get(u, []):
            if v not in par:
                par[v] = u; q.append(v)
    if not found:
        print(f'RVA 0x{trva:08x}  <UNREACHABLE>')
        continue
    # 回溯
    path = []
    cur = tva
    while cur is not None:
        path.append(cur); cur = par[cur]
    path.reverse()
    chain = ' -> '.join(f'0x{(v-IB):08x}(d{DEPTH.get(v,"?")})' for v in path)
    print(f'RVA 0x{trva:08x}  depth={DEPTH.get(tva,"?")}  path:  {chain}')
