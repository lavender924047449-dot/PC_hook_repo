# analyze_plaintext.py
import json, re, base64, glob, os

files = sorted(glob.glob('plaintext_*.json'), key=os.path.getmtime)
if not files:
    print('no files'); exit()

data = json.load(open(files[-1], encoding='utf-8'))
print(f'Total captures: {len(data)}')

def find_strs(hexdata, min_len=5):
    try:
        bs = bytes.fromhex(hexdata.replace(' ',''))
    except:
        return []
    results = []
    s = bs.decode('utf-8', errors='ignore')
    for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s):
        w = m.group().strip()
        if w: results.append(('u8', w))
    s16 = bs.decode('utf-16-le', errors='ignore')
    for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s16):
        w = m.group().strip()
        if w: results.append(('u16', w))
    return results[:10]

def try_decode_b64(s):
    m = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', s)
    if m:
        try:
            decoded = base64.b64decode(m.group() + '==')
            readable = ''.join(c for c in decoded.decode('utf-8', errors='ignore') if c.isprintable())
            if readable and len(readable) > 5:
                return readable
        except:
            pass
    return None

SKIP = re.compile(r'\.xml|bubble|layout|unread|industry|weclaw|ChatBubble|ChatImg|glyph|Rtl')

for i, cap in enumerate(data):
    addr_str = cap['a2_addr']
    print(f'\n=== capture #{i+1}  a2={addr_str} ===')
    print(f'  a2[0:48]: {cap["a2"][:143]}')
    
    interesting = []
    for paddr, hexd in cap.get('ptrs', {}).items():
        strs = find_strs(hexd)
        for enc, s in strs:
            if SKIP.search(s):
                continue
            if len(s) > 6:
                interesting.append((paddr, enc, s))
    
    for paddr, enc, s in interesting[:10]:
        b64 = try_decode_b64(s)
        if b64:
            print(f'  [b64 @{paddr}]: {b64[:120]!r}')
        else:
            print(f'  [{enc} @{paddr}]: {s[:100]!r}')
