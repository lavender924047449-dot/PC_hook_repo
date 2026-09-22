"""字节级对比 HIT #1 (文字→FTA) vs HIT #3 (文件→FTA) 的 args[1] 前 2KB。
找 msgtype 字段偏移。
"""
import sys
from pathlib import Path
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

D = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_114043'

h1 = (D/f'hook_presend_deep_{TS}_h1_a1.bin').read_bytes()
h3 = (D/f'hook_presend_deep_{TS}_h3_a1.bin').read_bytes()
print(f'h1_a1 len={len(h1)}  h3_a1 len={len(h3)}\n')

# 逐字节 diff（只显示不同处）
diffs = []
for i in range(min(len(h1), len(h3))):
    if h1[i] != h3[i]:
        diffs.append(i)

# 聚合成 runs
runs = []
if diffs:
    start = diffs[0]; prev = start
    for i in diffs[1:]:
        if i - prev > 4:
            runs.append((start, prev+1))
            start = i
        prev = i
    runs.append((start, prev+1))

print(f'[+] 总差异字节: {len(diffs)}  聚合为 {len(runs)} 段\n')
for st, ed in runs[:40]:
    print(f'  @0x{st:04x}..0x{ed:04x}  ({ed-st}B)')
    print(f'    HIT#1: {h1[st:min(ed,st+32)].hex()}')
    print(f'    HIT#3: {h3[st:min(ed,st+32)].hex()}')

# 特别看 conv_id 附近（±16 字节）
print('\n[+] conv_id 附近 (0x120..0x160):')
print(f'  HIT#1: {h1[0x120:0x160].hex()}')
print(f'  HIT#3: {h3[0x120:0x160].hex()}')
print(f'  HIT#1 ASCII: {"".join(chr(b) if 0x20<=b<=0x7e else "." for b in h1[0x120:0x160])!r}')
print(f'  HIT#3 ASCII: {"".join(chr(b) if 0x20<=b<=0x7e else "." for b in h3[0x120:0x160])!r}')

# 首 0x40 字节（msgid 附近）
print('\n[+] 前 0x40 字节 (msgid 头部):')
print(f'  HIT#1: {h1[:0x40].hex()}')
print(f'  HIT#3: {h3[:0x40].hex()}')

# 找 4/1/8 等小 int 字段（msgtype 通常是 4/8/9 for text/file 等）
print('\n[+] 前 0x140 里所有 int32 值:')
import struct
for off in range(0, 0x140, 4):
    v1 = struct.unpack('<I', h1[off:off+4])[0] if off+4 <= len(h1) else 0
    v3 = struct.unpack('<I', h3[off:off+4])[0] if off+4 <= len(h3) else 0
    if v1 != v3 and (v1 < 100 or v3 < 100):
        print(f'  @0x{off:04x}: HIT#1={v1} (0x{v1:x})  HIT#3={v3} (0x{v3:x})')

# 找 args[0] task 对象里的 diff (也可能存 msgtype)
print('\n' + '='*70)
print('[+] args[0] (task) HIT#1 vs HIT#3 diff:')
h1_a0 = (D/f'hook_presend_deep_{TS}_h1_a0.bin').read_bytes()
h3_a0 = (D/f'hook_presend_deep_{TS}_h3_a0.bin').read_bytes()
diffs0 = [i for i in range(min(len(h1_a0), len(h3_a0))) if h1_a0[i] != h3_a0[i]]
runs0 = []
if diffs0:
    st = diffs0[0]; pr = st
    for i in diffs0[1:]:
        if i-pr > 4: runs0.append((st, pr+1)); st = i
        pr = i
    runs0.append((st, pr+1))
print(f'  diff bytes: {len(diffs0)}, {len(runs0)} runs')
for st, ed in runs0[:20]:
    print(f'  @0x{st:04x}..0x{ed:04x}')
    print(f'    HIT#1: {h1_a0[st:min(ed,st+24)].hex()}')
    print(f'    HIT#3: {h3_a0[st:min(ed,st+24)].hex()}')
