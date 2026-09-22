import json, sys, re, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('plaintext_20260911_134541.json', 'r', encoding='utf-8') as f:
    caps = json.load(f)

print(f'Total captures: {len(caps)}')

def find_strs(hexdata, min_len=4):
    if not hexdata: return []
    hexdata = hexdata.replace(' ', '')
    try:
        bs = bytes.fromhex(hexdata)
    except:
        return []
    results = []
    # ASCII
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, bs):
        s = m.group().decode('ascii', errors='ignore')
        results.append(('ascii', m.start(), s))
    # UTF-16LE
    try:
        s16 = bs.decode('utf-16-le', errors='ignore')
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s16):
            results.append(('u16', m.start()*2, m.group()))
    except: pass
    return results

def try_pb(hexdata):
    if not hexdata: return []
    try: data = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    fields = []
    i = 0
    while i < len(data) and len(fields) < 20:
        if data[i] == 0: break
        try:
            tag = 0; shift = 0
            while i < len(data):
                b = data[i]; i += 1
                tag |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
                if shift > 35: raise ValueError('shift overflow')
            wire = tag & 7; field = tag >> 3
            if field == 0 or field > 5000: break
            if wire == 0:
                val = 0; shift2 = 0
                while i < len(data):
                    b = data[i]; i += 1
                    val |= (b & 0x7F) << shift2; shift2 += 7
                    if not (b & 0x80): break
                fields.append({'f': field, 't': 'varint', 'v': val})
            elif wire == 2:
                ln = 0; shift2 = 0
                while i < len(data):
                    b = data[i]; i += 1
                    ln |= (b & 0x7F) << shift2; shift2 += 7
                    if not (b & 0x80): break
                if ln > 100000 or i + ln > len(data): break
                pay = data[i:i+ln]; i += ln
                try:
                    s = pay.decode('utf-8', errors='strict')
                    fields.append({'f': field, 't': 'str', 'v': s})
                except:
                    fields.append({'f': field, 't': 'bytes', 'len': ln, 'hex': pay[:32].hex()})
            elif wire == 5: i += 4
            elif wire == 1: i += 8
            else: break
        except Exception as e:
            break
    return fields

for i, cap in enumerate(caps):
    ts = cap.get('ts', 0)
    a2_addr = cap.get('a2_addr', '?')
    a2h = cap.get('a2', '')
    a1h = cap.get('a1', '')
    a3h = cap.get('a3', '')
    ptrs = cap.get('ptrs', {})

    print(f'\n--- cap#{i}  a2_addr={a2_addr} ---')
    
    # 找字符串
    strs_a2 = find_strs(a2h)
    strs_a1 = find_strs(a1h)
    
    # 打印 a2 中的字符串
    for enc, off, s in strs_a2:
        if any(kw in s.lower() for kw in ['before', 'after', 'cgi', 'weixin', 'request', 'forward', 'compress', 'http']):
            print(f'  a2[0x{off:03x}] {enc}: {s[:120]}')
    
    # a2 中的 protobuf 尝试
    a2bytes = bytes.fromhex(a2h.replace(' ','')) if a2h else b''
    if len(a2bytes) >= 16:
        # 在 a2 的各个偏移处尝试 pb 解码
        for off in [0, 4, 8, 0x10, 0x20, 0x40, 0x60, 0x80, 0xa0]:
            sub = a2bytes[off:]
            if len(sub) < 4: continue
            fields = try_pb(sub.hex())
            if len(fields) >= 4:
                print(f'  [PB @ a2+0x{off:02x}]')
                for f in fields[:10]:
                    if f.get('t') == 'str':
                        print(f'    field{f["f"]}: {repr(f["v"][:80])}')
                    elif f.get('t') == 'bytes':
                        print(f'    field{f["f"]}(bytes,{f["len"]}): {f["hex"][:24]}')
                    else:
                        print(f'    field{f["f"]}(varint)={f["v"]}')
                break
    
    # ptrs deref
    if ptrs:
        print(f'  ptrs: {list(ptrs.keys())[:8]}')
        for pname, ph in list(ptrs.items())[:4]:
            strs_p = find_strs(ph)
            for enc, off, s in strs_p:
                if any(kw in s.lower() for kw in ['forward', 'weixin', 'request', 'http', 'before', '1001', '561']):
                    print(f'  ptrs[{pname}][0x{off:03x}]: {s[:100]}')
