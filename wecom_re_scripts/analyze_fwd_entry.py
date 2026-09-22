# analyze_fwd_entry.py - 分析 fwd_entry JSON，读 args[1] 缓冲区内容
import json, sys, struct
from pathlib import Path
from collections import Counter

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# 找最新的 fwd_entry 文件
files = sorted(Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re').glob('fwd_entry_*.json'))
if not files:
    print('No file found')
    sys.exit(1)
f = files[-1]
print(f'File: {f.name}')

data = json.load(open(f, encoding='utf-8'))
print(f'Records: {len(data)}')

# args[1] 是 begin 指针，args[2] = begin+0x70（end）
# 需要在 Frida 里读，这里只能看统计

# 统计 args[1] 分布（不同的 begin 指针）
begin_ptrs = Counter(d['args'][1] for d in data)
print(f'\n唯一 begin 指针: {len(begin_ptrs)}')
for ptr, cnt in sorted(begin_ptrs.items(), key=lambda x:-x[1])[:10]:
    diff = int(data[0]['args'][2], 16) - int(data[0]['args'][1], 16) if data else 0
    print(f'  {ptr} x{cnt}')

# 检查 args[3] 分布
arg3s = Counter(d['args'][3] for d in data)
print(f'\n唯一 args[3] 值: {dict(arg3s)}')

# 检查 ts 分布（时间戳，找转发时刻）
tss = [d['ts'] for d in data]
if tss:
    t0 = min(tss)
    print(f'\n时间分布（相对 ms）:')
    for d in data[:5]:
        print(f'  t={d["ts"]-t0}ms args={d["args"]}')

print(f'\n=== 注意: 需要在 Frida 中读 args[1] 指向的实际字节 ===')
print('args[2] - args[1] = 0x70 = 112 字节 缓冲区')
print('compact 可能在缓冲区内偏移 0/4/8/... 处')
