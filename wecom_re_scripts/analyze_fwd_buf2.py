# analyze_fwd_buf2.py - 分析 fwd_buf2 中新出现的地址的完整数据
import json, sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

data = json.load(open('fwd_buf2_20260911_181439.json', encoding='utf-8'))
print(f'Total events: {len(data)}')

# 只看新出现的 begin 地址 (Phase 2 有 data 且 non-zero 的)
# 重点: 0x19f9fb00 (x21) 和 0x2c4bf8d8 (x1)
TARGETS = {'0x19f9fb00', '0x2c4bf8d8', '0x17d9f980', '0x1851f5e8', '0x1879f858'}

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b&0x7F)<<sh; sh += 7
        if not(b&0x80): return v, pos
    return None, pos

def parse_proto(bs, label=''):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 30:
        if i < len(bs) and bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag&7; fn = tag>>3
            if fn == 0 or fn > 2000: break
            if w == 0:
                v, i = decode_varint(bs, i)
                if v is None: break
                fields.append((fn, 'v', v))
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 50000 or i2+ln > len(bs): break
                pay = bs[i2:i2+ln]; i = i2+ln
                try: fields.append((fn, 's', pay.decode('utf-8')))
                except: fields.append((fn, 'b', pay.hex()))
            elif w == 5:
                if i+4 <= len(bs):
                    v = struct.unpack_from('<I', bs, i)[0]; i += 4
                    fields.append((fn, 'i32', v))
                else: break
            elif w == 1:
                if i+8 <= len(bs):
                    v = struct.unpack_from('<Q', bs, i)[0]; i += 8
                    fields.append((fn, 'i64', v))
                else: break
            else: break
        except: break
    return fields

seen = {}
for e in data:
    begin = e.get('begin', '')
    if begin not in TARGETS: continue
    key = (begin, tuple(e.get('data') or [])[:8])
    if key in seen: continue
    seen[key] = True

    raw = e.get('data') or []
    inner = e.get('inner') or []
    elapsed = e.get('elapsed', 0) / 1000.0

    print(f'\n{"="*65}')
    print(f'begin={begin} t={elapsed:.1f}s sz={e.get("sz")}')
    if raw:
        bs = bytes(raw)
        print(f'  hex[0:64]: {bs[:64].hex()}')
        # 读作指针数组 (每4字节一个指针)
        print(f'  as ptrs:')
        for i in range(0, min(len(bs), 64), 4):
            pv = struct.unpack_from('<I', bs, i)[0]
            if 0x10000000 < pv < 0x7FFFFFFF:
                print(f'    [{i:3d}] 0x{pv:08x}  ← possible ptr')
            else:
                print(f'    [{i:3d}] 0x{pv:08x}')
        # 尝试 proto
        pf = parse_proto(bs)
        if pf:
            print(f'  proto fields:')
            for fn, wt, v in pf:
                if wt == 'v': print(f'    f{fn}={v} (0x{v:x})')
                elif wt == 's': print(f'    f{fn}={repr(v[:60])}')
                elif wt == 'b': print(f'    f{fn}=hex:{v[:32]}')
                elif wt in ('i32','i64'): print(f'    f{fn}={wt}:{v}')

    if inner:
        bs2 = bytes(inner)
        print(f'\n  inner[0:64]: {bs2[:64].hex()}')
        # 检查是否有 proto 迹象
        pf2 = parse_proto(bs2)
        if pf2:
            print(f'  inner proto:')
            for fn, wt, v in pf2:
                if wt == 'v': print(f'    f{fn}={v} (0x{v:x})')
                elif wt == 's': print(f'    f{fn}={repr(v[:60])}')
                elif wt == 'b': print(f'    f{fn}=hex:{v[:32]}')
        else:
            # 尝试读内部指针
            for i in range(0, min(len(bs2), 48), 4):
                pv = struct.unpack_from('<I', bs2, i)[0]
                if 0x10000000 < pv < 0x7FFFFFFF:
                    print(f'    inner[{i:3d}] 0x{pv:08x}')
