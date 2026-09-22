import json, sys, re, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('wait_cap_20260911_142216.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

cap = data['cgi'][0]
scan = cap.get('scan', [])

print(f'scan items: {len(scan)}')
print(f'a1_hex len: {len(cap.get("a1_hex","").replace(" ",""))//2}B')

# 打印完整 a1_hex（前 256B）
a1h = cap.get('a1_hex','')
a1b = bytes.fromhex(a1h.replace(' ',''))
print(f'\n--- a1 raw hex (first 256B) ---')
for i in range(0, min(256, len(a1b)), 16):
    hexpart = ' '.join(f'{b:02x}' for b in a1b[i:i+16])
    ascpart = ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in a1b[i:i+16])
    print(f'  {i:04x}: {hexpart:<48}  {ascpart}')

# 打印第一个 PROTO 候选的完整 hex
print('\n\n--- PROTO candidates (full hex) ---')
seen = set()
for s in scan:
    addr = s.get('addr','')
    if not s.get('hex') or addr in seen: continue
    seen.add(addr)
    raw = bytes.fromhex(s['hex'].replace(' ',''))
    print(f'\n[{s.get("path","")} → 0x{addr}] {len(raw)}B')
    for i in range(0, min(len(raw), 128), 16):
        hexpart = ' '.join(f'{b:02x}' for b in raw[i:i+16])
        ascpart = ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in raw[i:i+16])
        print(f'  {i:04x}: {hexpart:<48}  {ascpart}')
    if len(seen) >= 4: break
