# analyze_task_head.py — 精确列出每个 event 的 task[0:16] u32
import json
from pathlib import Path
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
target = sorted(OUT.glob('fwd_ab_v2_*.json'))[-1]
data = json.loads(target.read_text(encoding='utf-8'))
events = data['events']

def u32(b, o): return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

by_handler = {}
for e in events:
    by_handler.setdefault(e['handlerPtr'], []).append(e)

for h, evs in sorted(by_handler.items()):
    print(f'\n=== handler {h} ({len(evs)} events) ===')
    print(f'  {"phase":<7} {"begin":<12} {"t+0":<12} {"t+4":<12} {"t+8":<12} {"t+12":<12}')
    for e in evs:
        t = bytes(e['task'])
        vals = [u32(t, o) for o in (0,4,8,12)]
        vs = [f'0x{v:08x}' for v in vals]
        print(f'  P{e["phase"]:<6} {e["begin"]:<12} {vs[0]:<12} {vs[1]:<12} {vs[2]:<12} {vs[3]:<12}')
