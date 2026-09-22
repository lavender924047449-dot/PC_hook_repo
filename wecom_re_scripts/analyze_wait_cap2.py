# analyze_wait_cap2.py: 分析 wait_cap CGI 的 30 个 scan 项
import json, re, struct
from pathlib import Path

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
data = json.load(open(OUT / 'wait_cap_20260911_142216.json', encoding='utf-8'))
e = data['cgi'][0]
scan = e.get('scan', [])

a1_hex = e.get('a1_hex', '')
a1 = bytes.fromhex(a1_hex.replace(' ',''))

def tryPb(bs, limit=30, max_field=500):
    fields=[]; i=0
    while i<len(bs) and len(fields)<limit:
        if i<len(bs) and bs[i]==0: break
        try:
            tag=0; sh=0
            while i<len(bs):
                b=bs[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                if not(b&0x80): break
                if sh>35: raise ValueError
            w=tag&7; f=tag>>3
            if f==0 or f>max_field: break
            if w==0:
                v=0; sh2=0
                while i<len(bs):
                    b=bs[i]; i+=1; v|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                fields.append({'f':f,'t':'v','v':v})
            elif w==2:
                ln=0; sh2=0
                while i<len(bs):
                    b=bs[i]; i+=1; ln|=(b&0x7F)<<sh2; sh2+=7
                    if not(b&0x80): break
                if ln>100000 or i+ln>len(bs): break
                pay=bs[i:i+ln]; i+=ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s})
                except: 
                    sub = tryPb(pay, 10, max_field)
                    fields.append({'f':f,'t':'b','len':ln,'hex':pay[:20].hex(),'sub':sub})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

def printFields(fields, indent=0):
    pfx = '  ' * indent
    for f in fields:
        if f['t']=='s': print(f'{pfx}f{f["f"]}(str): {repr(f["v"][:100])}')
        elif f['t']=='v': print(f'{pfx}f{f["f"]}(int): {f["v"]}')
        elif f['t']=='b': 
            print(f'{pfx}f{f["f"]}(bytes,{f["len"]}): {f["hex"][:40]}')
            if f.get('sub'):
                printFields(f['sub'], indent+1)

def findStrs(bs):
    return [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{4,}', bs)]

def findUtf16(bs, min_chars=4):
    results = []
    i = 0
    while i < len(bs) - 1:
        if 0x20 <= bs[i] <= 0x7e and bs[i+1] == 0:
            start = i
            j = i
            while j+1 < len(bs) and 0x20 <= bs[j] <= 0x7e and bs[j+1] == 0:
                j += 2
            char_count = (j - start) // 2
            if char_count >= min_chars:
                s = bs[start:j].decode('utf-16-le', errors='ignore')
                results.append((start, s))
                i = j
                continue
        i += 1
    return results

print(f'a1 ({len(a1)}B): {a1[:16].hex()}')
print(f'scan items: {len(scan)}')

print('\n=== a1 raw analysis ===')
a1_strs = findStrs(a1)
a1_utf16 = findUtf16(a1)
a1_fields = tryPb(a1[4:])  # skip compact
if a1_strs:
    print('a1 ASCII strings:')
    for off, s in a1_strs[:5]: print(f'  +{off}: {s[:80]}')
if a1_utf16:
    print('a1 UTF-16 strings:')
    for off, s in a1_utf16[:5]: print(f'  +{off}: {s[:80]}')
if len(a1_fields) >= 2:
    print(f'a1 proto (at +4):')
    printFields(a1_fields[:10])

print('\n=== scan items ===')
for si, item in enumerate(scan):
    hex_data = item.get('hex', '')
    if not hex_data: continue
    bs = bytes.fromhex(hex_data.replace(' ',''))
    path = item.get('path', '')
    addr = item.get('addr', '')
    depth = item.get('depth', 0)
    
    # 分析内容
    ascii_strs = findStrs(bs)
    utf16_strs = findUtf16(bs)
    pb_fields = tryPb(bs)
    n_str = sum(1 for f in pb_fields if f['t']=='s')
    
    has_content = len(ascii_strs) > 0 or len(utf16_strs) > 0 or len(pb_fields) >= 3
    
    print(f'\n--- scan[{si}] path={path} addr={addr} depth={depth} ({len(bs)}B) ---')
    
    if ascii_strs:
        for off, s in ascii_strs[:4]:
            print(f'  ASCII+{off}: {s[:80]}')
    if utf16_strs:
        for off, s in utf16_strs[:6]:
            print(f'  UTF16+{off}: {s[:80]}')
    if len(pb_fields) >= 3:
        print(f'  [PROTO: {len(pb_fields)} fields, {n_str} str]:')
        printFields(pb_fields[:12], indent=1)
    elif len(pb_fields) > 0:
        print(f'  [partial proto: {len(pb_fields)} fields]:', pb_fields[:3])
    
    if not has_content:
        print(f'  raw hex: {hex_data[:40]}')
