import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
hits = [json.loads(l) for l in open(sys.argv[1], encoding='utf-8') if l.strip()]
target = sys.argv[2] if len(sys.argv) > 2 else '0x1833f5fc'
INTEREST = list(range(0x40, 0xc0, 4))

for i, h in enumerate(hits):
    if h['this_addr'] != target:
        continue
    print(f'\n=== hit #{i}  this={h["this_addr"]}  tid={h.get("tid")} ===')
    for f in h['fields']:
        if f['off'] not in INTEREST:
            continue
        parts = []
        if f.get('cstr'): parts.append(f'cstr={f["cstr"][:100]!r}')
        if f.get('w'):    parts.append(f'w={f["w"][:60]!r}')
        if not parts:
            continue
        print(f'  this+0x{f["off"]:02x}  raw={f.get("raw"):12s}  ' + '  '.join(parts))
