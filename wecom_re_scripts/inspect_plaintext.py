# inspect_plaintext.py - 分析 wsasend plaintext 数据结构
import json, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

data = json.load(open('plaintext_20260911_134541.json', encoding='utf-8'))
print(f'total: {len(data)}')

for i, item in enumerate(data[:5]):
    print(f'\n=== item {i} ===')
    for k, v in item.items():
        if isinstance(v, str):
            print(f'  {k}: {v[:120]}')
        elif isinstance(v, list):
            print(f'  {k}: list[{len(v)}]')
        elif isinstance(v, dict):
            print(f'  {k}: dict keys={list(v.keys())[:5]}')
        else:
            print(f'  {k}: {v}')
