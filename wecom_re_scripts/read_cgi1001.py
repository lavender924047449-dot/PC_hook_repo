import json, re, glob, os, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
files = sorted(glob.glob('cgi1001_*.json'), key=os.path.getmtime)
if not files:
    print('no files'); exit()
caps = json.load(open(files[-1], encoding='utf-8'))
print('captures:', len(caps))
if not caps:
    exit()

cap = caps[0]
print('keys:', list(cap.keys()))
a2_hex = cap.get('a2') or ''
a2_addr = cap.get('a2addr','')
print('a2_addr=%s  has1001=%s  hasURL=%s' % (a2_addr, cap.get('has1001'), cap.get('hasURL')))

if a2_hex:
    bs = bytes.fromhex(a2_hex.replace(' ',''))
    print('a2 bytes:', len(bs))
    for off in range(0, min(320, len(bs)), 16):
        row = bs[off:off+16]
        hx = ' '.join('%02x' % b for b in row)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in row)
        print('  %04x: %-47s  %s' % (off, hx, asc))
    s = bs.decode('utf-8', errors='ignore')
    tokens = [t for t in re.findall(r'[\x20-\x7e\u4e00-\u9fff]{6,}', s)]
    print('UTF-8 tokens:', tokens[:25])

print()
print('deref ptrs:', len(cap.get('ptrs', {})))
for addr, hexd in sorted(cap.get('ptrs', {}).items()):
    bs2 = bytes.fromhex(hexd.replace(' ', ''))
    s = ''.join(c for c in bs2.decode('utf-8', errors='ignore') if c.isprintable())
    if len(s) > 8 and not re.search(r'\.xml|weclaw|bubble|glyph|RtlAlloc|ChatBubble', s):
        print('  @0x%s: %r' % (addr, s[:130]))
