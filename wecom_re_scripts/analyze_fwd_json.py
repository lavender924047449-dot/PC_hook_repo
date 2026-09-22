# analyze_fwd_json.py - 深度分析 hook_real_fwd 捕获数据
import json, re, struct
from pathlib import Path

CAP = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\hook_real_fwd_20260911_163954.json')
data = json.loads(CAP.read_text(encoding='utf-8'))
cap = data[0]

print(f'ptr_derefs count: {len(cap.get("ptr_derefs", []))}')
print(f'backtrace: {cap.get("backtrace", [])}')
print()

def hex_dump(bs, max_bytes=400):
    for i in range(0, min(max_bytes, len(bs)), 16):
        chunk = bs[i:i+16]
        h = ' '.join(f'{b:02x}' for b in chunk)
        a = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in chunk)
        print(f'  {i:04x}: {h:<48}  {a}')

def find_utf16(bs, minchars=4):
    results = []; i = 0
    while i < len(bs) - 1:
        if 0x20 <= bs[i] <= 0x7e and bs[i+1] == 0:
            start = i; j = i
            while j+1 < len(bs) and 0x20 <= bs[j] <= 0x7e and bs[j+1] == 0: j += 2
            if (j-start) >= minchars*2: results.append((start, bs[start:j].decode('utf-16-le','ignore'))); i=j; continue
        i += 1
    return results

def find_ascii(bs, minlen=4):
    return [(m.start(), m.group().decode('ascii','ignore'))
            for m in re.finditer(rb'[\x20-\x7e]{' + str(minlen).encode() + rb',}', bs)]

# ── a1 原始数据分析 ────────────────────────────────────────────────────────────
a1 = bytes(cap.get('a1') or [])
print(f'=== a1 ({len(a1)}B) ===')
print('First 128 bytes:')
hex_dump(a1, 128)
print()
print('UTF-16 strings in a1:')
for off, s in find_utf16(a1):
    print(f'  +{off}: {s[:80]}')
print()

# ── 所有 ptr_derefs 分析 ───────────────────────────────────────────────────────
print(f'=== ptr_derefs ({len(cap.get("ptr_derefs",[]))} items) ===')
for dr in cap.get('ptr_derefs', []):
    off = dr.get('off', 0)
    ptr_val = dr.get('ptr', '?')
    bs = bytes(dr.get('data', []))
    if not bs: continue
    
    u16 = find_utf16(bs)
    ascii_s = find_ascii(bs, 6)
    
    # 找有趣的字符串
    useful_u16 = [(o, s) for o, s in u16 if any(kw in s.lower() for kw in
        ['conv','user','id','msg','room','chat','wx','ww','corp','to','from',
         'openid','weixin','forward','select','member','contact'])]
    useful_ascii = [(o, s) for o, s in ascii_s if any(kw in s.lower() for kw in
        ['conv','user','id','msg','room','chat','wx','ww','corp','openid','weixin'])]
    
    # 检测 proto
    def tryPb(bs):
        fields=[]; i=0
        while i<len(bs) and len(fields)<20:
            if bs[i]==0: break
            try:
                tag=0; sh=0
                while i<len(bs):
                    b=bs[i]; i+=1; tag|=(b&0x7F)<<sh; sh+=7
                    if not(b&0x80): break
                w=tag&7; f=tag>>3
                if f==0 or f>500: break
                if w==0:
                    v=0; sh=0
                    while i<len(bs): b=bs[i]; i+=1; v|=(b&0x7F)<<sh; sh+=7
                    if not(b&0x80): sh=99
                    fields.append((f,'v',v))
                elif w==2:
                    ln=0; sh=0
                    while i<len(bs): b=bs[i]; i+=1; ln|=(b&0x7F)<<sh; sh+=7
                    if not(b&0x80): sh=99
                    if ln>50000 or i+ln>len(bs): break
                    pay=bs[i:i+ln]; i+=ln
                    try: s=pay.decode('utf-8'); fields.append((f,'s',s))
                    except: fields.append((f,'b',pay[:8].hex()))
                elif w==5: i+=4
                elif w==1: i+=8
                else: break
            except: break
        return fields
    
    pb = tryPb(bs)
    
    if useful_u16 or useful_ascii or len(pb) >= 3:
        print(f'\n  ptr@+0x{off:03x} → {ptr_val} ({len(bs)}B):')
        for o, s in useful_u16[:4]: print(f'    u16+{o}: {s[:70]}')
        for o, s in useful_ascii[:3]: print(f'    asc+{o}: {s[:70]}')
        if len(pb) >= 3:
            print(f'    proto({len(pb)}f):')
            for fnum, t, v in pb[:15]:
                if t=='v': print(f'      f{fnum}={v}')
                elif t=='s': print(f'      f{fnum}={repr(v[:50])}')
                elif t=='b': print(f'      f{fnum}=bytes({v})')
    elif not any([useful_u16, useful_ascii]) and len(pb) < 3:
        # 打印简短摘要
        print(f'  ptr@+0x{off:03x} → {ptr_val}: [no useful strings, {len(pb)} pb fields]')

# 特别分析 +0x70 (可能含 conv_id)
print('\n=== 特别分析 ptr@+0x70 ===')
for dr in cap.get('ptr_derefs', []):
    if dr.get('off') == 0x70:
        bs = bytes(dr.get('data', []))
        print(f'ptr val: {dr.get("ptr")} ({len(bs)}B)')
        hex_dump(bs, 400)
        u16 = find_utf16(bs, 3)
        print('UTF-16:')
        for off, s in u16: print(f'  +{off}: {s}')
        break

# ── 也分析 arg_extra ──────────────────────────────────────────────────────────
print('\n=== arg_extra ===')
for ai, ae in enumerate(cap.get('arg_extra', [])):
    if not ae: continue
    bs = bytes(ae)
    u16 = find_utf16(bs)
    ascii_s = find_ascii(bs, 5)
    if u16 or ascii_s:
        print(f'arg_extra[{ai}] ({len(bs)}B):')
        for o, s in u16[:3]: print(f'  u16+{o}: {s[:60]}')
        for o, s in ascii_s[:3]: print(f'  asc+{o}: {s[:60]}')
