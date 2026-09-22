# deep_analyze_cap.py - 深度分析 wait_cap 文件，找出 conv_id / msg_id 的完整结构
# 重点：CGI 01004179 对应的 a1 参数结构
import json, re, struct
from pathlib import Path

CAP_FILE = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\wait_cap_20260911_142216.json')
data = json.loads(CAP_FILE.read_text(encoding='utf-8'))

print(f'总记录: {len(data)} 条')

def to_bytes(lst):
    if lst is None: return b''
    return bytes(lst)

def find_ascii(bs, minlen=4):
    return [(m.start(), m.group().decode('ascii','ignore')) 
            for m in re.finditer(rb'[\x20-\x7e]{' + str(minlen).encode() + rb',}', bs)]

def find_utf16(bs, minchars=4):
    results = []
    i = 0
    while i < len(bs) - 1:
        if 0x20 <= bs[i] <= 0x7e and bs[i+1] == 0:
            start = i; j = i
            while j+1 < len(bs) and 0x20 <= bs[j] <= 0x7e and bs[j+1] == 0:
                j += 2
            if (j - start) >= minchars * 2:
                results.append((start, bs[start:j].decode('utf-16-le', 'ignore')))
                i = j; continue
        i += 1
    return results

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1
        v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80): return v, pos
    return None, pos

def parse_proto(bs, depth=0, max_depth=3, limit=30):
    """解析 protobuf，返回字段列表"""
    fields = []; i = 0; count = 0
    while i < len(bs) and count < limit:
        if bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            wire = tag & 7; fnum = tag >> 3
            if fnum == 0 or fnum > 1000: break
            if wire == 0:  # varint
                v, i = decode_varint(bs, i)
                fields.append({'f': fnum, 't': 'v', 'v': v})
            elif wire == 2:  # length-delimited
                ln, i = decode_varint(bs, i)
                if ln is None or ln > 100000 or i + ln > len(bs): break
                payload = bs[i:i+ln]; i += ln
                # try utf-8
                try:
                    s = payload.decode('utf-8')
                    fields.append({'f': fnum, 't': 's', 'v': s, 'raw': payload[:8].hex()})
                except:
                    # try nested proto
                    if depth < max_depth and ln >= 2:
                        sub = parse_proto(payload, depth+1, max_depth, limit=10)
                        if len(sub) >= 2:
                            fields.append({'f': fnum, 't': 'msg', 'fields': sub, 'len': ln})
                        else:
                            fields.append({'f': fnum, 't': 'b', 'len': ln, 'hex': payload[:16].hex()})
                    else:
                        fields.append({'f': fnum, 't': 'b', 'len': ln, 'hex': payload[:16].hex()})
            elif wire == 5:  # 32-bit
                if i + 4 > len(bs): break
                v = struct.unpack_from('<I', bs, i)[0]; i += 4
                fields.append({'f': fnum, 't': 'i32', 'v': v})
            elif wire == 1:  # 64-bit
                if i + 8 > len(bs): break
                v = struct.unpack_from('<Q', bs, i)[0]; i += 8
                fields.append({'f': fnum, 't': 'i64', 'v': v})
            else: break
            count += 1
        except: break
    return fields

def fmt_fields(fields, indent='  '):
    lines = []
    for f in fields:
        t = f.get('t')
        if t == 'v': lines.append(f"{indent}f{f['f']}={f['v']}")
        elif t == 's': lines.append(f"{indent}f{f['f']}={repr(f['v'][:60])}")
        elif t == 'i32': lines.append(f"{indent}f{f['f']}=i32({f['v']})")
        elif t == 'i64': lines.append(f"{indent}f{f['f']}=i64({f['v']})")
        elif t == 'b': lines.append(f"{indent}f{f['f']}=bytes[{f['len']}] {f['hex']}")
        elif t == 'msg':
            lines.append(f"{indent}f{f['f']}=msg[{f['len']}]:")
            for sf in f.get('fields', []): lines.extend(fmt_fields([sf], indent+'  '))
    return lines

# 打印每条 01004179 的捕获
fwd_caps = [d for d in data if d.get('pattern') == '01004179']
print(f'\n01004179 捕获: {len(fwd_caps)} 条\n')

for ci, cap in enumerate(fwd_caps[:5]):
    print(f'{"="*70}')
    print(f'Cap #{ci}: args0={cap.get("args0")} args1={cap.get("args1")}')
    
    # a1 原始数据
    a1 = to_bytes(cap.get('a1') or [])
    if a1:
        ascii_a1 = find_ascii(a1)
        utf16_a1 = find_utf16(a1)
        
        print(f'\na1 ({len(a1)}B):')
        for off, s in ascii_a1:
            if len(s) > 4:
                print(f'  ascii@{off}: {s[:80]}')
        for off, s in utf16_a1:
            print(f'  utf16@{off}: {s[:70]}')
        
        # 解析 a1 内的指针（每4字节一个）
        print(f'\na1 内指针扫描:')
        ptrs_found = []
        for off in range(0, min(256, len(a1)), 4):
            v = struct.unpack_from('<I', a1, off)[0]
            if 0x10000 < v < 0x80000000:
                ptrs_found.append((off, v))
        
        for off, ptr in ptrs_found[:30]:
            print(f'  +0x{off:02x}: ptr → 0x{ptr:08x}', end='')
            sub_data = to_bytes(cap.get(f'ptr_{off}') or cap.get(f'sub_{off}') or [])
            if sub_data:
                ascii_sub = find_ascii(sub_data, minlen=4)
                useful = [(o,s) for o,s in ascii_sub if len(s) > 5]
                if useful:
                    print(f' → {useful[0][1][:50]}')
                else:
                    print()
            else:
                print()
    
    # deref 数据（scan 结果）
    scan_items = cap.get('scan') or cap.get('items') or []
    if scan_items:
        print(f'\nscan items ({len(scan_items)}):')
        for si, item in enumerate(scan_items[:30]):
            ptr_addr = item.get('ptr') or item.get('addr', '?')
            sub = to_bytes(item.get('data') or item.get('bytes') or [])
            if not sub: continue
            
            ascii_s = find_ascii(sub, minlen=4)
            utf16_s = find_utf16(sub)
            pb = parse_proto(sub)
            
            useful_ascii = [(o,s) for o,s in ascii_s if len(s) > 4 and any(
                c in s.lower() for c in ['conv','user','id','room','chat','msg','wx','ww','qq','to','from','corp'])]
            
            if useful_ascii or utf16_s or len(pb) >= 2:
                print(f'\n  item[{si}] @ {ptr_addr} ({len(sub)}B):')
                for o, s in useful_ascii[:3]: print(f'    ascii@{o}: {s[:60]}')
                for o, s in utf16_s[:2]: print(f'    utf16@{o}: {s[:60]}')
                if len(pb) >= 2:
                    print(f'    PROTO({len(pb)} fields):')
                    for line in fmt_fields(pb[:12], '      '): print(line)

print('\n\n[=== 全部 scan 数据汇总 ===]')

# 汇总所有 scan item 的 proto 结构
all_protos = []
for cap in fwd_caps:
    scan_items = cap.get('scan') or cap.get('items') or []
    for item in scan_items:
        sub = to_bytes(item.get('data') or item.get('bytes') or [])
        if sub:
            pb = parse_proto(sub)
            if len(pb) >= 3:
                all_protos.append({'ptr': item.get('ptr', '?'), 'fields': pb, 'raw': sub[:16].hex()})

print(f'有效 proto 结构: {len(all_protos)} 个')
for p in all_protos[:20]:
    print(f"\n  ptr={p['ptr']} raw={p['raw']}")
    for line in fmt_fields(p['fields'][:10]): print(line)
