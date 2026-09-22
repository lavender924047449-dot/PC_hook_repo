# analyze_cgi_wait.py: 分析 cgi_wait JSON，找 ForwardMessageReq
import json, re
from pathlib import Path

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

data = json.load(open(OUT / 'cgi_wait_20260911_133158.json', encoding='utf-8'))

def tryPb(bs, limit=25):
    fields=[]; i=0
    while i<len(bs) and len(fields)<limit:
        if bs[i]==0: break
        try:
            tag=0; sh=0
            while i<len(bs):
                b=bs[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                if not(b&0x80): break
                if sh>35: raise ValueError
            w=tag&7; f=tag>>3
            if f==0 or f>500: break
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
                if ln>50000 or i+ln>len(bs): break
                pay=bs[i:i+ln]; i+=ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s})
                except: fields.append({'f':f,'t':'b','len':ln,'hex':pay[:16].hex()})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

def findStrings(bs):
    return [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]

for pattern, entries in data.items():
    print(f'\n{"="*60}')
    print(f'Pattern: {pattern} ({len(entries)} entries)')
    
    for ei, e in enumerate(entries[:2]):
        a1_hex = e.get('a1_512', '')
        a1 = bytes.fromhex(a1_hex.replace(' ','')) if a1_hex else b''
        
        # 扫描指针并读取内容
        scan_items = e.get('scan_items', [])
        
        print(f'\n  --- Entry #{ei} ---')
        print(f'  a1 len: {len(a1)}')
        
        # a1 字符串
        strs = findStrings(a1)
        if strs:
            print('  a1 strings:')
            for off, s in strs[:6]:
                print(f'    +{off}: {s[:80]}')
        
        # a1 proto 解析
        for start in [0, 4, 8, 16]:
            fields = tryPb(a1[start:])
            if len(fields) >= 4:
                print(f'  a1 proto at +{start}: {len(fields)} fields')
                for f in fields[:8]:
                    if f['t']=='s': print(f'    f{f["f"]}: {repr(f["v"][:50])}')
                    elif f['t']=='v': print(f'    f{f["f"]}={f["v"]}')
                    elif f['t']=='b': print(f'    f{f["f"]}(b,{f["len"]}): {f["hex"]}')
                break
        
        # scan_items 中找有意义的数据
        print(f'  scan_items: {len(scan_items)}')
        for si, item in enumerate(scan_items[:30]):
            hex_data = item.get('hex', '')
            if not hex_data: continue
            bs = bytes.fromhex(hex_data.replace(' ',''))
            
            # 字符串检查
            strs2 = findStrings(bs)
            useful = [(off,s) for off,s in strs2 if any(kw in s.lower() for kw in ['weixin','userid','conv','msg','forward','chat','openid','wxid','corp'])]
            
            # proto
            fields = tryPb(bs)
            n_str = sum(1 for f in fields if f['t']=='s')
            
            if useful or len(fields) >= 5:
                print(f'\n    scan[{si}] offset=0x{item.get("offset", 0):x} v=0x{item.get("v", 0):x}:')
                for off, s in useful[:3]:
                    print(f'      str+{off}: {s[:80]}')
                if len(fields) >= 5:
                    print(f'      [PROTO: {len(fields)} fields, {n_str} str]')
                    for f in fields[:8]:
                        if f['t']=='s': print(f'        f{f["f"]}: {repr(f["v"][:50])}')
                        elif f['t']=='v': print(f'        f{f["f"]}={f["v"]}')
                        elif f['t']=='b': print(f'        f{f["f"]}(b,{f["len"]}): {f["hex"]}')

print('\n[Done]')
