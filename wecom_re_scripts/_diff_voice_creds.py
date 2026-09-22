# _diff_voice_creds.py — 跨多次 forward 对比 CIGAE 串 & 16B 高熵块（aeskey 候选）
import re
from pathlib import Path
from collections import defaultdict

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

# 找到所有 SER arg0 dump，按 (session_ts, vt) 分组
files = sorted(OUT_DIR.glob('voice_recon_*_h*_SER_vt*_arg0.bin'))
by_run_vt = defaultdict(list)
for fp in files:
    m = re.match(r'voice_recon_(\d+_\d+)_h(\d+)_SER_vt([0-9a-f]+)_arg0', fp.name)
    if m:
        ts, hn, vt = m.group(1), int(m.group(2)), m.group(3)
        by_run_vt[(ts, vt)].append((hn, fp))

# 特征提取：CIGAE 串 + 稳定 16B 高熵块 + FILEASSIST 位置
CIGAE_RE = re.compile(rb'CIGAE[A-Za-z0-9+/=]{15,45}')
FILE_ASSIST = b'FILEASSIST'

def extract(data):
    cigae = sorted(set(m.group().decode() for m in CIGAE_RE.finditer(data)))
    fa_offsets = []
    p = 0
    while True:
        p = data.find(FILE_ASSIST, p)
        if p < 0: break
        fa_offsets.append(p)
        p += 1
    # 找 magiccube URL
    urls = re.findall(rb'https?://[a-zA-Z0-9._/-]+', data)
    urls = sorted(set(u.decode('latin-1', errors='replace') for u in urls if b'magic' in u or b'wework' in u or b'rtx' in u))
    return cigae, fa_offsets, urls

runs = sorted(set(k[0] for k in by_run_vt.keys()))
print(f'找到 {len(runs)} 个 session, {len(files)} 个 dump\n')

for ts in runs:
    print(f'{"="*80}\n▶ session {ts}\n{"="*80}')
    vts_in_run = sorted(vt for (t, vt) in by_run_vt.keys() if t == ts)
    for vt in vts_in_run:
        for hn, fp in by_run_vt[(ts, vt)]:
            data = fp.read_bytes()
            cigae, fa, urls = extract(data)
            tag = f'vt=0x{vt}  h={hn:02d}'
            if cigae or fa or urls:
                print(f'\n  {tag}:')
                if cigae:
                    print(f'    CIGAE strings ({len(cigae)}):')
                    for c in cigae: print(f'      {c}')
                if fa:
                    print(f'    FILEASSIST occurrences: {len(fa)}  offsets={[hex(x) for x in fa[:6]]}')
                if urls:
                    print(f'    URLs: {urls}')

# 跨 session 对 vt=0xb06c9b8 (sub-msg A) 提取 header 32B (含高熵 aeskey 候选)
print(f'\n\n{"="*80}\n▶ 跨 session 对比 vt=0xb06c9b8 header 32B (aeskey 候选)\n{"="*80}')
for ts in runs:
    for vt in ['0b06c9b8']:
        for hn, fp in by_run_vt.get((ts, vt), []):
            data = fp.read_bytes()
            # 前 64 字节里跳过 leading zeros 找非零段
            header32 = data[0x18:0x18+32]
            print(f'  {ts}  h={hn:02d}  @+0x18: {header32.hex()}')

print(f'\n\n{"="*80}\n▶ 跨 session 对比 vt=0xb0610c0 (outer) 前 64B\n{"="*80}')
for ts in runs:
    for vt in ['0b0610c0']:
        for hn, fp in by_run_vt.get((ts, vt), []):
            data = fp.read_bytes()
            print(f'  {ts}  h={hn:02d}  first64: {data[:64].hex()}')

print('\n[done]')
