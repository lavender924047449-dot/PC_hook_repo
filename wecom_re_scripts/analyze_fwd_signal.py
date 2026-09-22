# analyze_fwd_signal.py — 分析 fwd_signal_*.json 的 NEW task / meta，找新版转发 magic
import json, sys, struct
from pathlib import Path
from collections import Counter

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
target = sorted(OUT.glob('fwd_signal_*.json'))[-1]
print(f'[+] 分析 {target.name}')
data = json.loads(target.read_text(encoding='utf-8'))
caps = data['captures']
print(f'  captures={len(caps)}  tags top: {data["tagCounts"]}')

def u32(b, o):
    return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

# 1. begin 频次统计
begins = Counter(c['begin'] for c in caps)
print(f'\n[begin 频次]')
for b, n in begins.most_common():
    print(f'  {b}: {n}')

# 2. 尝试各种 magic 在 meta 中搜索
CANDIDATE_MAGICS = [
    bytes.fromhex('d0070002'),  # 旧版
    bytes.fromhex('d0070003'),
    bytes.fromhex('d1070002'),
    bytes.fromhex('e0070002'),
    bytes.fromhex('cf070002'),
    bytes.fromhex('c0070002'),
    bytes.fromhex('a0070002'),
]

print(f'\n[magic 扫描：在 meta 前 1024B 中搜索候选 magic]')
magic_hits = Counter()
for c in caps:
    m = c.get('meta')
    if not m: continue
    m = bytes(m)
    for mg in CANDIDATE_MAGICS:
        idx = m.find(mg)
        if idx >= 0:
            magic_hits[(mg.hex(), idx)] += 1
for (mg, off), n in magic_hits.most_common(20):
    print(f'  magic={mg} off={off}: {n} 次')

# 3. 每个 task 前 32 字节 hex + task+52 处 metaPtr 提取
print(f'\n[前 10 条 task/meta 结构详情]')
for i, c in enumerate(caps[:10]):
    task = bytes(c.get('task') or [])
    meta = bytes(c.get('meta') or [])
    if len(task) < 60 or len(meta) < 32:
        continue
    print(f'\n#{i+1} begin={c["begin"]} sz={c["sz"]} metaPtr={c["metaPtr"]}')
    print(f'  task[0:64]  = {task[:64].hex()}')
    # meta 前 128 字节 hex 分行
    for j in range(0, min(128, len(meta)), 32):
        # 提取本行 ASCII 可打印
        seg = meta[j:j+32]
        ascii_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in seg)
        print(f'  meta[+{j:03d}] = {seg.hex()}  | {ascii_s}')

# 4. 在所有 meta 中搜 4 字节 ASCII 可打印字符串（潜在新 tag4）
print(f'\n[所有 meta 中的 4 字符 ASCII 段（新版可能 tag4）]')
tag_hits = Counter()
for c in caps:
    m = bytes(c.get('meta') or [])
    for i in range(len(m) - 3):
        four = m[i:i+4]
        if all(0x21 <= b <= 0x7e for b in four):
            # 排除路径/单字节堆积
            s = four.decode('ascii', errors='replace')
            if s.count('.') <= 1:  # 排除 .dll .exe 类
                tag_hits[s] += 1
for s, n in tag_hits.most_common(30):
    if n >= 2:
        print(f'  {repr(s)}: {n}')

# 5. 特别检查：payload+92 (346833984 = 0x14ac4440) 是否出现（源 FTA conv id）
print(f'\n[搜索源 FTA conv=0x14ac4440 或 wecom_message_id=0xb87232c]')
FTA_CONV = 0x14ac4440
FTA_ID = 0xb87232c
for c in caps:
    for name in ('task', 'meta'):
        b = bytes(c.get(name) or [])
        for off in range(0, len(b) - 4, 4):
            v = u32(b, off)
            if v == FTA_CONV:
                print(f'  {name} +{off} = 0x{v:08x} (FTA_CONV) in {c["begin"]}')
            elif v == FTA_ID:
                print(f'  {name} +{off} = 0x{v:08x} (FTA_ID) in {c["begin"]}')

# 6. 保存精简分析结果
summary = {
    'source': target.name,
    'total_caps': len(caps),
    'begins_top': begins.most_common(20),
    'magic_hits': [{'magic': k[0], 'off': k[1], 'n': v} for k, v in magic_hits.most_common()],
    'ascii_tags_top': [{'s': k, 'n': v} for k, v in tag_hits.most_common(50)],
}
out_summary = OUT / target.name.replace('.json', '_summary.json')
out_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] summary: {out_summary}')
