# _find_msgtype.py — 从 SER this dump 里找 msgtype 字段
# 每个 outbound proto 的 `this` 前 128B 里应含 msgtype (小 int)
import struct, re
from pathlib import Path
from collections import defaultdict

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

# 4 个 outbound vtable 的 this dump
files = sorted(OUT_DIR.glob('voice_recon_*_SER_vt*_this.bin'))
print(f'扫描 {len(files)} 个 SER this dumps\n')

# 按 vt 分组
by_vt = defaultdict(list)
for fp in files:
    m = re.search(r'_vt([0-9a-f]+)_', fp.name)
    if m: by_vt[m.group(1)].append(fp)

def dump_hex(data, per_line=16, max_lines=8):
    lines = []
    for i in range(0, min(len(data), per_line*max_lines), per_line):
        chunk = data[i:i+per_line]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        ascs = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append(f'  +{i:04x}  {hexs:<48}  {ascs}')
    return lines

for vt, fps in by_vt.items():
    print(f'\n{"="*76}\n▶ vt=0x{vt}  ({len(fps)} dumps)  可能类型: {"outer" if vt=="0b0610c0" else "sub-A" if vt=="0b06c9b8" else "repeated" if vt=="0b0656a8" else "ExtraContent" if vt=="0b0901ac" else "?"}\n{"="*76}')
    for fp in fps:
        data = fp.read_bytes()
        print(f'\n─ {fp.name} ─')
        print('  header 128B:')
        for line in dump_hex(data, per_line=16, max_lines=8):
            print(line)
        # 找 msgtype 候选：小 int (1..300) 在前 64 字节
        print(f'  ── uint32 候选 (offset < 64, value 1..300)：')
        cands = []
        for off in range(4, 64, 4):  # skip vtable at 0
            v = struct.unpack('<I', data[off:off+4])[0]
            if 1 <= v <= 300:
                print(f'    +{off:04x} = {v}')
                cands.append((off, v))

# 交叉：所有 dumps 里 offset 相同 & value 相同的字段 → 稳定的 msgtype 候选
print(f'\n\n{"="*76}\n★ 跨 dump 稳定小 int 字段（可能是 msgtype 或固定 enum）\n{"="*76}')
all_vals = defaultdict(dict)  # {vt: {offset: [values...]}}
for vt, fps in by_vt.items():
    for fp in fps:
        data = fp.read_bytes()
        for off in range(4, 128, 4):
            v = struct.unpack('<I', data[off:off+4])[0]
            all_vals[vt].setdefault(off, []).append(v)

for vt, offs in all_vals.items():
    print(f'\n vt=0x{vt}:')
    for off, vals in sorted(offs.items()):
        if all(1 <= v <= 300 for v in vals):
            uniq = set(vals)
            note = '★ 完全一致' if len(uniq) == 1 else '有变化'
            print(f'    +{off:04x} = {vals}  {note}')
