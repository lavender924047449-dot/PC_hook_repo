#!/usr/bin/env python3
# 对比 DRY_RUN 与 真 patch 两轮的 arg0_before / arg0_after，看 msgtype patch 有没有落到 wire
from pathlib import Path

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

DRY = '20260914_143032'   # DRY_RUN 15→15
RUN = '20260914_143354'   # 真 patch 15→34

def load(prefix, kind):
    p = OUT / f'msgtype_patch_{prefix}_{kind}.bin'
    return p.read_bytes() if p.exists() else b''

def scan_varint_at(data, tag):
    """在 data 前 128B 里找 tag byte，返回所有位置和跟随字节"""
    hits = []
    for i in range(min(len(data)-2, 128)):
        if data[i] == tag:
            hits.append((i, data[i+1], data[i+2] if i+2 < len(data) else 0))
    return hits

def hexdump(data, n=128):
    out = []
    for i in range(0, min(len(data), n), 16):
        row = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        out.append(f'  {i:04x}  {hex_part:<48} {asc}')
    return '\n'.join(out)

def diff_bytes(a, b, n=128):
    """标出 a b 前 n 字节不同的位置"""
    diffs = []
    for i in range(min(len(a), len(b), n)):
        if a[i] != b[i]:
            diffs.append((i, a[i], b[i]))
    return diffs

for tag, ts in [('DRY-RUN 15→15', DRY), ('真 patch 15→34', RUN)]:
    print(f'\n{"="*72}\n{tag}   ts={ts}\n{"="*72}')
    b_before = load(ts, 'ser1_arg0_before')
    b_after  = load(ts, 'arg0_after')
    print(f'  arg0_before: {len(b_before)}B    arg0_after: {len(b_after)}B')
    print(f'\n  === arg0_BEFORE (SER 未执行前) 前 128B ===')
    print(hexdump(b_before, 128))
    print(f'\n  === arg0_AFTER (SER 执行后) 前 128B ===')
    print(hexdump(b_after, 128))
    # 找 tag=0x08 field1 varint
    hits_before = scan_varint_at(b_before, 0x08)
    hits_after  = scan_varint_at(b_after,  0x08)
    print(f'\n  before 里 tag=0x08 出现: {hits_before[:6]}')
    print(f'  after  里 tag=0x08 出现: {hits_after[:6]}')
    diffs = diff_bytes(b_before, b_after, 256)
    print(f'\n  before/after 前 256B 差异位置: {len(diffs)} bytes')
    for i, a, b in diffs[:16]:
        print(f'    @+{i:#x}  {a:02x} → {b:02x}')

# 关键：对比 DRY 的 after 和 RUN 的 after，是否 wire 里真的把 15 换成了 34
print(f'\n{"="*72}\n★ 决定性对比：DRY_RUN.after  vs  真patch.after')
print(f'{"="*72}')
dry_after = load(DRY, 'arg0_after')
run_after = load(RUN, 'arg0_after')
diffs = diff_bytes(dry_after, run_after, 512)
print(f'  两轮 arg0_after 的 wire 差异位置: {len(diffs)} bytes')
for i, a, b in diffs[:32]:
    print(f'    @+{i:#x}  DRY={a:02x}  RUN={b:02x}   ({"★msgtype-flip" if (a==15 and b==34) or (a==0x0f and b==0x22) else ""})')
