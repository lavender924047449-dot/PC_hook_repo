# analyze_fwd3b.py: 正确格式分析 fwd_capture3
import json, re, struct
from pathlib import Path

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
data = json.load(open(OUT / 'fwd_capture3_20260911_125444.json', encoding='utf-8'))

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

FWD_PATTERNS = {'01004179','01006300','01006c00','01006d00','01016135','0161a92e','01cbb414'}

# 对每个 fwd pattern 找第一个有意义的 entry
analyzed = {}
for e in data:
    p = e.get('compact','').replace(' ','')
    if p not in FWD_PATTERNS: continue
    if p not in analyzed:
        analyzed[p] = []
    analyzed[p].append(e)

print('\n=== 各 CGI 模式深度分析 ===')

for p, entries in analyzed.items():
    print(f'\n{"="*60}')
    print(f'Pattern: {p} ({len(entries)} entries)')
    
    for ei, e in enumerate(entries[:2]):
        print(f'\n  Entry #{ei}:')
        for field_name in ['a0', 'a1', 'a2_deref']:
            hex_str = e.get(field_name, '')
            if not hex_str: continue
            try:
                bs = bytes.fromhex(hex_str.replace(' ',''))
            except: continue
            
            strs = findStrs(bs)
            useful_strs = [(off,s) for off,s in strs if any(kw in s.lower() for kw in 
                ['weixin','userid','conv','msg','forward','chat','openid','wxid','corp','http','key','cgi'])]
            
            fields = tryPb(bs)
            n_str = sum(1 for f in fields if f['t']=='s')
            
            if useful_strs or len(fields) >= 4:
                label = f'  [{field_name}] {len(bs)}B'
                if useful_strs: label += f' [STRS:{len(useful_strs)}]'
                if len(fields) >= 4: label += f' [PROTO:{len(fields)}f,{n_str}s]'
                print(label)
                for off, s in useful_strs[:4]:
                    print(f'    str+{off}: {s[:80]}')
                if len(fields) >= 4:
                    for f in fields[:8]:
                        if f['t']=='s': print(f'    f{f["f"]}: {repr(f["v"][:50])}')
                        elif f['t']=='v': print(f'    f{f["f"]}={f["v"]}')
                        elif f['t']=='b': print(f'    f{f["f"]}(b,{f["len"]}): {f["hex"]}')
            else:
                # 只打印 raw hex
                print(f'  [{field_name}] {len(bs)}B: {hex_str[:60]}...')
        
        # 分析 4 字节对齐的指针
        a1_hex = e.get('a1', '')
        if a1_hex:
            a1 = bytes.fromhex(a1_hex.replace(' ',''))
            print(f'  a1 pointers (4B LE):')
            for off in range(0, min(64, len(a1)), 4):
                pv = struct.unpack_from('<I', a1, off)[0]
                if 0x01000000 < pv < 0xE0000000:
                    print(f'    a1+{off}: 0x{pv:08x} (possible ptr)')

print('\n[Done]')
