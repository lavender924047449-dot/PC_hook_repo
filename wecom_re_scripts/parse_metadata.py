# parse_metadata.py - 解析 dump_task 中 inner[off=52] metadata 块
import json, struct, sys, re
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

MAGIC = bytes([0xd0, 0x07, 0x00, 0x02])  # d0070002

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80):
            return v, pos
    return None, pos

def parse_proto(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 50:
        if bs[i] == 0:
            break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None:
                break
            w = tag & 7; fn = tag >> 3
            if fn == 0 or fn > 5000:
                break
            if w == 0:
                v, i = decode_varint(bs, i)
                if v is None:
                    break
                fields.append((fn, 'v', v))
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 200000 or i2 + ln > len(bs):
                    break
                pay = bs[i2:i2 + ln]; i = i2 + ln
                try:
                    fields.append((fn, 's', pay.decode('utf-8')))
                except Exception:
                    fields.append((fn, 'b', pay))
            elif w == 5:
                if i + 4 <= len(bs):
                    v = struct.unpack_from('<I', bs, i)[0]; i += 4
                    fields.append((fn, 'i32', v))
                else:
                    break
            elif w == 1:
                if i + 8 <= len(bs):
                    v = struct.unpack_from('<Q', bs, i)[0]; i += 8
                    fields.append((fn, 'i64', v))
                else:
                    break
            else:
                break
        except Exception:
            break
    return fields

def u16_strings(bs):
    out = []
    i = 0
    while i + 4 <= len(bs):
        if bs[i] == 0 and bs[i+1] == 0:
            i += 2
            continue
        if bs[i+1] == 0 and 32 <= bs[i] < 127:
            chars = []
            j = i
            while j + 1 < len(bs):
                lo, hi = bs[j], bs[j+1]
                if hi != 0 or lo == 0:
                    break
                if lo < 32 or lo >= 127:
                    break
                chars.append(chr(lo)); j += 2
            if len(chars) >= 4:
                out.append((''.join(chars), i))
            i = j
        else:
            i += 2
    return out

def ascii_strings(bs, min_len=4):
    out = []
    cur = []
    start = 0
    for i, b in enumerate(bs):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append((''.join(cur), start))
            cur = []
    if len(cur) >= min_len:
        out.append((''.join(cur), start))
    return out

def find_magic_off(bs):
    idx = bs.find(MAGIC)
    return idx if idx >= 0 else None

def scan_compacts(bs):
    hits = []
    for i in range(0, len(bs) - 3):
        b0, b1, b2, b3 = bs[i:i+4]
        if b0 == 0x01 and not (b1 == 0 and b2 == 0 and b3 == 0):
            hits.append((i, f'{b0:02x}{b1:02x}{b2:02x}{b3:02x}'))
    return hits

def analyze_block(label, bs):
    print(f'\n{"="*70}')
    print(f'{label}  len={len(bs)}')
    print(f'  head32: {bs[:32].hex()}')

    u16 = bs[0] and struct.unpack_from('<I', bs, 0)[0]
    u16b = struct.unpack_from('<I', bs, 4)[0] if len(bs) >= 8 else 0
    print(f'  u32[0]={u16}  u32[1]={u16b}')

    mo = find_magic_off(bs)
    if mo is not None:
        print(f'  magic d0070002 @ offset {mo}')
        ctx = bs[max(0, mo-16):mo+48]
        print(f'  magic ctx: {ctx.hex()}')
        # 解析 magic 后字段
        after = bs[mo+4:mo+64]
        print(f'  after magic (+4..+64): {after.hex()}')
        for i in range(0, min(len(after), 32), 4):
            pv = struct.unpack_from('<I', after, i)[0]
            tag = ' ptr' if 0x10000000 < pv < 0x7F000000 else ''
            print(f'    [+{4+i:02d}] 0x{pv:08x}{tag}')

    compacts = scan_compacts(bs)
    if compacts:
        print(f'  compact candidates ({len(compacts)}):')
        for off, c in compacts[:12]:
            print(f'    off={off:3d}  {c}')

    for s, off in ascii_strings(bs):
        if len(s) >= 4:
            print(f'  ascii@{off}: {repr(s[:80])}')
    for s, off in u16_strings(bs):
        print(f'  utf16@{off}: {repr(s[:80])}')

    pf = parse_proto(bs)
    if pf:
        print('  proto:')
        for fn, wt, v in pf[:20]:
            if wt == 'v':
                print(f'    f{fn}={v} (0x{v:x})')
            elif wt == 's':
                print(f'    f{fn}={repr(v[:80])}')
            elif wt == 'b':
                print(f'    f{fn}=bytes[{len(v)}]:{v[:16].hex()}')
            else:
                print(f'    f{fn}={wt}:{v}')

# load latest dump
files = sorted(Path('.').glob('dump_task_*.json'))
if not files:
    print('No dump_task_*.json found')
    sys.exit(1)
path = files[-1]
print(f'Loading {path.name}')
data = json.load(open(path, encoding='utf-8'))

for cap in data:
    begin = cap['begin']
    print(f'\n######## TASK begin={begin} t={cap["elapsed"]/1000:.1f}s ########')
    raw = bytes(cap.get('data') or [])
    if raw:
        meta_off = 52
        if len(raw) >= meta_off + 4:
            meta_ptr = struct.unpack_from('<I', raw, meta_off)[0]
            print(f'  task[+52] metadata_ptr = 0x{meta_ptr:08x}')

    for p in cap.get('ptrs', []):
        if p['off'] != 52:
            continue
        bs = bytes(p['bytes'])
        analyze_block(f'metadata @ {p["ptr"]} (task {begin})', bs)

    # 也分析 off=0 的 inner（之前发现 icon 路径）
    for p in cap.get('ptrs', []):
        if p['off'] != 0:
            continue
        bs = bytes(p['bytes'])
        analyze_block(f'inner[0] @ {p["ptr"]} (task {begin})', bs)
