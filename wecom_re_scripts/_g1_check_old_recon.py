# 检查 voice_recon_20260914_13*_*.bin 里到底有没有真正的 voice payload 字节
import sys, re
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

MARKERS = [b'.silk', b'.amr', b'SILK', b'#!SILK', b'aeskey', b'silk_url', b'silkmd5',
           b'file_id', b'voice_id', b'voiceid', b'voice_length', b'duration',
           b'cdn_key', b'cdnkey', b'wxwork', b'.qpic.cn', b'wework.qq.com',
           b'FILEASSIST', b'ConvMessageVoice', b'MessageBody']

for fp in sorted(OUT.glob('voice_recon_20260914_*.bin')):
    data = fp.read_bytes()
    tail = len(data)
    while tail > 0 and data[tail-1] == 0: tail -= 1
    hits = []
    for m in MARKERS:
        p = 0
        while True:
            p = data.find(m, p)
            if p < 0: break
            hits.append((p, m.decode('latin-1')))
            p += 1
    # 也搜 UTF-8 [语音]
    if b'\x5b\xe8\xaf\xad\xe9\x9f\xb3\x5d' in data:
        hits.append((data.find(b'\x5b\xe8\xaf\xad\xe9\x9f\xb3\x5d'), '★[语音]-UTF8'))
    strs = [m.group() for m in re.finditer(rb'[\x20-\x7e]{8,}', data[:tail])][:15]
    print(f'{fp.name}  size={len(data)}  tail={tail}  markers={len(hits)}')
    for off, m in hits[:8]:
        ctx = data[max(0,off-6):off+len(m.encode())+32]
        print(f'    @+0x{off:04x}  {m!r}  ctx={ctx.hex()}')
    for s in strs[:5]:
        print(f'    str: {s[:120]!r}')
    print()
