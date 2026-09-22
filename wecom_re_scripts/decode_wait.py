import json, sys, re, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('wait_cap_20260911_142216.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

caps = data.get('cgi', [])
print(f'CGI captures: {len(caps)}')

def try_pb(data_bytes, depth=0, limit=50):
    fields = []; i = 0
    while i < len(data_bytes) and len(fields) < limit:
        if data_bytes[i] == 0: break
        try:
            tag = 0; shift = 0
            while i < len(data_bytes):
                b = data_bytes[i]; i += 1
                tag |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
                if shift > 35: raise ValueError
            wire = tag & 7; field = tag >> 3
            if field == 0 or field > 5000: break
            if wire == 0:
                val = 0; sh2 = 0
                while i < len(data_bytes):
                    b = data_bytes[i]; i += 1
                    val |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                fields.append({'f':field,'t':'varint','v':val})
            elif wire == 2:
                ln = 0; sh2 = 0
                while i < len(data_bytes):
                    b = data_bytes[i]; i += 1
                    ln |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                if ln > 100000 or i+ln > len(data_bytes): break
                pay = data_bytes[i:i+ln]; i += ln
                try:
                    s = pay.decode('utf-8')
                    fields.append({'f':field,'t':'str','v':s,'raw':pay.hex()})
                except:
                    # 尝试子 proto
                    sub = try_pb(pay, depth+1, 10) if depth < 2 else []
                    fields.append({'f':field,'t':'bytes','len':ln,'hex':pay[:64].hex(),'sub':sub})
            elif wire == 5:
                val = struct.unpack_from('<I', data_bytes, i)[0]; i += 4
                fields.append({'f':field,'t':'fixed32','v':val})
            elif wire == 1:
                val = struct.unpack_from('<Q', data_bytes, i)[0]; i += 8
                fields.append({'f':field,'t':'fixed64','v':val})
            else: break
        except: break
    return fields

def print_pb(fields, indent=0):
    pfx = '  '*indent
    for f in fields:
        if f['t'] == 'str':
            print(f'{pfx}f{f["f"]} (str): {repr(f["v"][:120])}')
        elif f['t'] == 'varint':
            print(f'{pfx}f{f["f"]} (int): {f["v"]}  (0x{f["v"]:x})')
        elif f['t'] == 'fixed32':
            print(f'{pfx}f{f["f"]} (f32): {f["v"]}  (0x{f["v"]:08x})')
        elif f['t'] == 'fixed64':
            print(f'{pfx}f{f["f"]} (f64): {f["v"]}')
        elif f['t'] == 'bytes':
            sub = f.get('sub',[])
            print(f'{pfx}f{f["f"]} (bytes, {f["len"]}B): {f["hex"][:32]}...')
            if sub:
                print(f'{pfx}  [sub-proto]')
                print_pb(sub, indent+2)

for ci, cap in enumerate(caps[:5]):
    print(f'\n{"="*70}')
    print(f'Cap#{ci}  compact={cap.get("compact")}')
    
    # 1) 直接解析 a1_hex
    a1h = cap.get('a1_hex','')
    if a1h:
        a1b = bytes.fromhex(a1h.replace(' ',''))
        print(f'\n--- a1 直接解析 ({len(a1b)}B) ---')
        # 跳过 4B 命令字
        for skip in [0, 4, 8, 16]:
            fields = try_pb(a1b[skip:])
            if len(fields) >= 3:
                print(f'  [skip {skip}B -> {len(fields)} fields]')
                print_pb(fields[:15])
                break
        # 找 ASCII 字符串
        for m in re.finditer(rb'[\x20-\x7e]{6,}', a1b):
            s = m.group().decode('ascii','ignore')
            if any(kw in s.lower() for kw in ['cgi','forward','weixin','before','compress','1001','http','msg','from','to','chat']):
                print(f'  STR[+0x{m.start():03x}]: {s[:120]}')
        # UTF-16LE
        try:
            u16 = a1b.decode('utf-16-le', errors='ignore')
            for m in re.finditer(r'[\d]+:[\d]+:[0-9]', u16):
                print(f'  MsgId (u16): {m.group()}')
        except: pass
    
    # 2) scan 候选
    print(f'\n--- scan 候选 ({len(cap.get("scan",[]))} items) ---')
    seen_addrs = set()
    for s in cap.get('scan', []):
        addr = s.get('addr','')
        hexdata = s.get('hex','')
        sstr = s.get('str','')
        path = s.get('path','')
        if addr in seen_addrs: continue
        if sstr:
            print(f'  STR [{path}]: {sstr[:100]}')
            continue
        if not hexdata: continue
        seen_addrs.add(addr)
        raw = bytes.fromhex(hexdata.replace(' ',''))
        fields = try_pb(raw)
        if len(fields) >= 2:
            print(f'\n  [PROTO @ {path} → 0x{addr}] ({len(raw)}B, {len(fields)} fields)')
            print_pb(fields[:20])
            # 找字符串
            for m in re.finditer(rb'[\x20-\x7e]{6,}', raw):
                ss = m.group().decode('ascii','ignore')
                if any(kw in ss.lower() for kw in ['cgi','forward','weixin','before','compress','from','to','msg','chat','open','id']):
                    print(f'    STR[+0x{m.start():03x}]: {ss[:100]}')
        else:
            # 非 proto，但检查字符串
            strs = []
            for m in re.finditer(rb'[\x20-\x7e]{6,}', raw):
                ss = m.group().decode('ascii','ignore')
                if any(kw in ss.lower() for kw in ['forward','weixin','1001','cgi','http','msg','from','to','chat']):
                    strs.append(f'+0x{m.start():03x}:{ss[:80]}')
            if strs:
                print(f'  [STRINGS @ {path} → 0x{addr}]')
                for ss in strs[:3]: print(f'    {ss}')
