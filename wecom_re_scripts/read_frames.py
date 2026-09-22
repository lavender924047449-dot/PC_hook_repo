import json, sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def tryPb(bs, limit=20):
    fields = []; i = 0
    while i < len(bs) and len(fields) < limit:
        if bs[i] == 0: break
        try:
            tag = 0; sh = 0
            while i < len(bs):
                b = bs[i]; i += 1
                tag |= (b & 0x7F) << sh; sh += 7
                if not (b & 0x80): break
                if sh > 35: raise ValueError
            w = tag & 7; f = tag >> 3
            if f == 0 or f > 3000: break
            if w == 0:
                v = 0; sh2 = 0
                while i < len(bs):
                    b = bs[i]; i += 1
                    v |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                fields.append({'f':f,'t':'v','v':v})
            elif w == 2:
                ln = 0; sh2 = 0
                while i < len(bs):
                    b = bs[i]; i += 1
                    ln |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                if ln > 50000 or i+ln > len(bs): break
                pay = bs[i:i+ln]; i += ln
                try: s=pay.decode('utf-8'); fields.append({'f':f,'t':'s','v':s,'raw':pay.hex()})
                except: fields.append({'f':f,'t':'b','len':ln,'hex':pay[:32].hex()})
            elif w == 5: i += 4; fields.append({'f':f,'t':'f32'})
            elif w == 1: i += 8; fields.append({'f':f,'t':'f64'})
            else: break
        except: break
    return fields

# --- hook_frames (hook_send_frames 的结果) ---
with open('hook_frames_20260911_134321.json', 'r', encoding='utf-8') as f:
    caps = json.load(f)
print(f'hook_frames: {len(caps)} captures')

for i, cap in enumerate(caps[:9]):
    label = cap.get('label','?')
    print(f'\n-- cap#{i} label={label} ecx={cap.get("ecx","")} esi={cap.get("esi","")}')
    for key in ['ecx_data','esi_data','args']:
        val = cap.get(key)
        if not val: continue
        if isinstance(val, str):
            bs = bytes.fromhex(val.replace(' ',''))
            print(f'  {key}({len(bs)}B): {val[:80]}')
            # 字符串
            for m in re.finditer(rb'[\x20-\x7e]{6,}', bs):
                s = m.group().decode('ascii')
                print(f'    str[+0x{m.start():02x}]: {s[:80]}')
            # proto
            fields = tryPb(bs)
            if len(fields) >= 4:
                print(f'  [PROTO in {key}]')
                for ff in fields[:8]:
                    if ff.get('t') == 's':
                        print(f'    f{ff["f"]}: {repr(ff["v"][:80])}')
                    elif ff.get('t') == 'b':
                        print(f'    f{ff["f"]}(bytes,{ff["len"]}): {ff["hex"][:24]}')
                    else:
                        print(f'    f{ff["f"]}={ff.get("v","")}')
        elif isinstance(val, list):
            for j, a in enumerate(val[:4]):
                if isinstance(a, str):
                    bs = bytes.fromhex(a.replace(' ',''))
                    print(f'  args[{j}]({len(bs)}B): {a[:80]}')
                    for m in re.finditer(rb'[\x20-\x7e]{5,}', bs):
                        s = m.group().decode('ascii')
                        print(f'    str[+0x{m.start():02x}]: {s[:80]}')
