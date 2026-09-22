# analyze_wait_cap.py v2: 深度分析 wait_cap_20260911_142216.json
import json, re, struct
from pathlib import Path

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
data = json.load(open(OUT / 'wait_cap_20260911_142216.json', encoding='utf-8'))

cgi_entries = data.get('cgi', [])
print(f'CGI entries: {len(cgi_entries)}')

def tryPb(bs, limit=30):
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
            if f==0 or f>1000: break
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
                    sub = tryPb(pay, 15)
                    fields.append({'f':f,'t':'b','len':ln,'hex':pay[:24].hex(),'sub':sub})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

def printFields(fields, indent=0):
    pfx = '  ' * indent
    for f in fields:
        if f['t']=='s': 
            val = repr(f['v'][:80])
            print(f'{pfx}f{f["f"]}(str): {val}')
        elif f['t']=='v': print(f'{pfx}f{f["f"]}(int): {f["v"]}')
        elif f['t']=='b': 
            print(f'{pfx}f{f["f"]}(bytes,{f["len"]}): {f["hex"][:40]}')
            if f.get('sub'):
                printFields(f['sub'], indent+1)

def findStrs(bs):
    return [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]

for ei, e in enumerate(cgi_entries):
    print(f'\n{"="*60}')
    print(f'CGI Entry #{ei}: compact={e.get("compact")}')
    print(f'Keys: {list(e.keys())}')
    
    # a1_hex
    a1 = bytes.fromhex(e.get('a1_hex','').replace(' ',''))
    print(f'a1 ({len(a1)}B): {a1[:20].hex()}')
    
    # scan_items
    scan_items = e.get('scan_items', [])
    print(f'scan_items: {len(scan_items)}')
    
    for si, item in enumerate(scan_items):
        hex_data = item.get('hex', '')
        if not hex_data: continue
        bs = bytes.fromhex(hex_data.replace(' ',''))
        
        # find strings
        strs = findStrs(bs)
        # find utf-16 strings (forward message related)
        utf16_strs = []
        for start_off in range(0, len(bs)-2, 2):
            if bs[start_off+1] == 0 and 0x20 <= bs[start_off] <= 0x7e:
                # possible utf-16le string start
                end = start_off
                while end+1 < len(bs) and bs[end+1] == 0 and 0x20 <= bs[end] <= 0x7e:
                    end += 2
                if (end - start_off) >= 10:  # at least 5 chars
                    s = bs[start_off:end].decode('utf-16-le', errors='ignore')
                    utf16_strs.append((start_off, s))
        
        # proto parse
        fields = tryPb(bs)
        n_str = sum(1 for f in fields if f['t']=='s')
        
        if strs or utf16_strs or len(fields) >= 3:
            print(f'\n  scan[{si}] offset=0x{item.get("off", item.get("offset", 0)):x} v=0x{item.get("v", 0):08x} ({len(bs)}B):')
            for off, s in strs[:4]:
                print(f'    ASCII+{off}: {s[:80]}')
            for off, s in utf16_strs[:4]:
                print(f'    UTF16+{off}: {s[:80]}')
            if len(fields) >= 3:
                print(f'    [PROTO {len(fields)}f, {n_str}s]:')
                printFields(fields[:15], indent=2)
