# analyze_fwd3.py: 分析 fwd_capture3 中所有转发专属 CGI 的内容
import json, re, struct
from pathlib import Path

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
data = json.load(open(OUT / 'fwd_capture3_20260911_125444.json', encoding='utf-8'))
print(f'Total entries: {len(data)}')

FWD_PATTERNS = {'01004179','01006300','01006c00','01006d00','01016135','0161a92e','01cbb414'}

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
                except: fields.append({'f':f,'t':'b','len':ln,'hex':pay[:20].hex()})
            elif w==5: i+=4
            elif w==1: i+=8
            else: break
        except: break
    return fields

def findStrs(bs):
    return [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]

# 统计每个 pattern 出现的次数
from collections import Counter
pattern_cnt = Counter()
for e in data:
    p = e.get('compact','').replace(' ','')
    pattern_cnt[p] += 1

print('\nPattern counts:')
for p, cnt in pattern_cnt.most_common():
    print(f'  {p}: {cnt}')

# 对每个 fwd pattern 找第一个有意义的 entry
print('\n\n=== 分析各 CGI 模式的 args[1] ===')
analyzed = set()
for e in data:
    p = e.get('compact','').replace(' ','')
    if p not in FWD_PATTERNS or p in analyzed: continue
    analyzed.add(p)
    
    print(f'\n{"="*60}')
    print(f'Pattern: {p}')
    
    # args 数据
    args = e.get('args', [])
    for ai, arg in enumerate(args[:6]):
        h = arg.get('h', '') if isinstance(arg, dict) else ''
        v = arg.get('v', 0) if isinstance(arg, dict) else 0
        if not h: continue
        bs = bytes.fromhex(h.replace(' ',''))
        
        strs = findStrs(bs)
        fields = tryPb(bs)
        n_str = sum(1 for f in fields if f['t']=='s')
        
        if strs or len(fields) >= 3:
            label = f'arg[{ai}] v=0x{v:08x}'
            if strs: label += f' [STRS:{len(strs)}]'
            if len(fields) >= 3: label += f' [PROTO:{len(fields)}f,{n_str}s]'
            print(f'\n  {label}')
            for off, s in strs[:5]:
                print(f'    +{off}: {s[:80]}')
            if len(fields) >= 3:
                print(f'  Fields:')
                for f in fields[:8]:
                    if f['t']=='s': print(f'    f{f["f"]}: {repr(f["v"][:50])}')
                    elif f['t']=='v': print(f'    f{f["f"]}={f["v"]}')
                    elif f['t']=='b': print(f'    f{f["f"]}(b,{f["len"]}): {f["hex"]}')
    
    # begin_hex / end_hex 如果存在
    for key in ['begin_hex', 'end_hex', 'payload_hex']:
        hx = e.get(key, '')
        if hx:
            bs = bytes.fromhex(hx.replace(' ',''))
            strs = findStrs(bs)
            fields = tryPb(bs)
            n_str = sum(1 for f in fields if f['t']=='s')
            print(f'\n  {key} ({len(bs)} bytes):')
            for off, s in strs[:4]:
                print(f'    +{off}: {s[:80]}')
            if len(fields) >= 3:
                for f in fields[:8]:
                    if f['t']=='s': print(f'    f{f["f"]}: {repr(f["v"][:50])}')
                    elif f['t']=='v': print(f'    f{f["f"]}={f["v"]}')

print('\n[Done]')
