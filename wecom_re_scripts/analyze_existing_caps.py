# analyze_existing_caps.py
# 分析已有的捕获数据，提取 ForwardMessage proto 结构
# 目标文件：
# - wait_cap_20260911_142216.json  (已知含 f13=336445 的转发数据)
# - fwd_capture3_20260911_125444.json (147条转发专属抓包)
# - snap_on_go_20260911_171832.json (新捕获，含01414f32)

import json, struct, sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b & 0x7F) << sh; sh += 7
        if not (b & 0x80): return v, pos
    return None, pos

def parse_proto(bs, depth=0):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 50:
        if i >= len(bs) or bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag & 7; fn = tag >> 3
            if fn == 0 or fn > 5000: break
            if w == 0:
                v, i = decode_varint(bs, i)
                if i is None: break
                fields.append({'f': fn, 't': 'v', 'v': v})
            elif w == 2:
                ln, i2 = decode_varint(bs, i)
                if ln is None or ln > 500000 or i2 + ln > len(bs): break
                pay = bs[i2:i2+ln]; i = i2 + ln
                try:
                    s = pay.decode('utf-8')
                    fields.append({'f': fn, 't': 's', 'v': s})
                except:
                    fields.append({'f': fn, 't': 'b', 'v': pay, 'hex': pay[:16].hex()})
            elif w == 5:
                if i+4 <= len(bs):
                    v = struct.unpack_from('<I', bs, i)[0]; i += 4
                    fields.append({'f': fn, 't': 'i32', 'v': v})
                else: break
            elif w == 1:
                if i+8 <= len(bs):
                    v = struct.unpack_from('<Q', bs, i)[0]; i += 8
                    fields.append({'f': fn, 't': 'i64', 'v': v})
                else: break
            else: break
        except: break
    return fields

def print_proto(fields, indent='  '):
    for f in fields:
        fn = f['f']; t = f['t']; v = f['v']
        if t == 'v':
            print(f'{indent}f{fn} = {v}  (0x{v:x})')
        elif t == 's':
            print(f'{indent}f{fn} = str:{repr(v[:80])}')
        elif t == 'b':
            print(f'{indent}f{fn} = bytes[{len(v)}]: {f["hex"]}')
            # 尝试子 proto
            sub = parse_proto(v)
            if len(sub) >= 2:
                print(f'{indent}  [sub-proto]:')
                print_proto(sub, indent + '    ')
        elif t == 'i32':
            print(f'{indent}f{fn} = i32:{v}  (0x{v:x})')
        elif t == 'i64':
            print(f'{indent}f{fn} = i64:{v}  (0x{v:x})')

def analyze_bytes(bs, label):
    if not bs or len(bs) < 4: return
    # 尝试 proto（从头）
    fields = parse_proto(bs)
    # 尝试跳过 4 字节 compact 再 parse
    fields4 = parse_proto(bs[4:]) if len(bs) >= 8 else []
    
    if len(fields) >= 2 or len(fields4) >= 2:
        print(f'\n  [{label}]:')
        if len(fields) >= 2:
            print(f'  proto from 0:')
            print_proto(fields)
        if len(fields4) >= 2 and fields4 != fields:
            print(f'  proto from +4B:')
            print_proto(fields4)
    else:
        # 看有没有 ASCII 字符串
        try:
            text = bs.decode('utf-8', errors='replace')
            if any(c.isalpha() for c in text[:32]):
                print(f'  [{label}]: {text[:60]}')
        except: pass

# ─── 1. 分析 wait_cap_20260911_142216.json ─────────────────────────────────────

print('='*70)
print('1. wait_cap_20260911_142216.json')
print('='*70)

try:
    data = json.loads((DIR / 'wait_cap_20260911_142216.json').read_text(encoding='utf-8'))
    print(f'  类型: {type(data).__name__}')
    
    if isinstance(data, list):
        print(f'  条目数: {len(data)}')
        for i, item in enumerate(data[:3]):
            print(f'\n  [条目 {i}]: keys={list(item.keys()) if isinstance(item, dict) else type(item)}')
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, list) and len(v) > 4:
                        print(f'    {k}: list[{len(v)}] → 分析...')
                        analyze_bytes(bytes(v), k)
                    elif isinstance(v, (str, int, float)):
                        print(f'    {k}: {v}')
    elif isinstance(data, dict):
        print(f'  keys: {list(data.keys())}')
        for k, v in data.items():
            if isinstance(v, list) and len(v) > 4:
                print(f'  {k}: list[{len(v)}]')
                analyze_bytes(bytes(v), k)
except Exception as e:
    print(f'  [ERR] {e}')

# ─── 2. 分析 fwd_capture3 ──────────────────────────────────────────────────────

print('\n' + '='*70)
print('2. fwd_capture3_20260911_125444.json (前 5 条)')
print('='*70)

try:
    data = json.loads((DIR / 'fwd_capture3_20260911_125444.json').read_text(encoding='utf-8'))
    print(f'  类型: {type(data).__name__}')
    
    if isinstance(data, list):
        print(f'  条目数: {len(data)}')
        for i, item in enumerate(data[:5]):
            print(f'\n  [条目 {i}]: {list(item.keys()) if isinstance(item, dict) else type(item)}')
            if isinstance(item, dict):
                # 打印简单字段
                for k, v in item.items():
                    if isinstance(v, (str, int, float, bool)):
                        print(f'    {k}: {v}')
                # 分析 bytes 字段
                for k, v in item.items():
                    if isinstance(v, list) and len(v) > 4:
                        bs = bytes(v)
                        analyze_bytes(bs, f'{k}[{len(bs)}B]')
    elif isinstance(data, dict):
        print(f'  keys: {list(data.keys())}')
except Exception as e:
    print(f'  [ERR] {e}')

# ─── 3. 分析 snap_on_go 里的 01414f32 ─────────────────────────────────────────

print('\n' + '='*70)
print('3. snap_on_go 里的特殊 compact (01414f32, 01ed4135)')
print('='*70)

try:
    data = json.loads((DIR / 'snap_on_go_20260911_171832.json').read_text(encoding='utf-8'))
    special = [e for e in data if e.get('compact') in ('01414f32', '01ed4135')]
    print(f'  特殊条目数: {len(special)}')
    for e in special[:5]:
        print(f'\n  compact={e["compact"]} a3={e["a3"]} a3_24={e["a3_24"]} ts={e["ts"]}ms')
        if e.get('a1b'):
            bs = bytes(e['a1b'])
            h = ' '.join(f'{b:02x}' for b in bs[:64])
            print(f'  a1[0:64]: {h}')
            analyze_bytes(bs, 'a1')
            analyze_bytes(bs[4:], 'a1+4B')
        if e.get('a3b'):
            bs = bytes(e['a3b'])
            h = ' '.join(f'{b:02x}' for b in bs[:64])
            print(f'  a3[0:64]: {h}')
            analyze_bytes(bs, 'a3')
except Exception as e:
    print(f'  [ERR] {e}')

# ─── 4. 分析 hook_real_fwd 里的深层数据 ──────────────────────────────────────

print('\n' + '='*70)
print('4. hook_real_fwd_20260911_163954.json (a1 和 ptr_derefs)')
print('='*70)

try:
    data = json.loads((DIR / 'hook_real_fwd_20260911_163954.json').read_text(encoding='utf-8'))
    if isinstance(data, list) and len(data) > 0:
        item = data[0]
        print(f'  keys: {list(item.keys())}')
        for k, v in item.items():
            if isinstance(v, (str, int)):
                print(f'  {k}: {v}')
            elif isinstance(v, list) and len(v) > 4:
                bs = bytes(v)
                print(f'\n  {k}: {len(bs)}B')
                h = ' '.join(f'{b:02x}' for b in bs[:48])
                print(f'    hex[0:48]: {h}')
                analyze_bytes(bs, k)
            elif isinstance(v, dict):
                print(f'  {k}: dict({len(v)} keys)')
except Exception as e:
    print(f'  [ERR] {e}')
