# _find_cdn.py — 从所有 voice_recon dump 里挖 CDN URL / audio file ref / silk 特征
import re
from pathlib import Path

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

# 找所有 voice_recon dumps
files = sorted(OUT_DIR.glob('voice_recon_*_arg0.bin')) + sorted(OUT_DIR.glob('voice_recon_*_this.bin'))
print(f'扫描 {len(files)} 个 dump\n')

CDN_RE = re.compile(rb'(https?://)?[a-zA-Z0-9_-]+\.(?:rtxapp|wework|weworkcdn|tencent|qq|wxcdn)[a-zA-Z0-9._/-]{0,300}')
FID_RE = re.compile(rb'[a-zA-Z0-9_/+=-]{20,200}')  # 潜在 file_id / long token
MEDIA_MARKERS = [b'SILK', b'#!SILK', b'.silk', b'.amr', b'.mp3', b'wav', b'aac',
                 b'voice_id', b'voiceid', b'audio_id', b'mediaid', b'mediaId',
                 b'file_id', b'fileId', b'fid=', b'aeskey=', b'aeskey', b'md5=',
                 b'duration', b'MsgVoice', b'AudioMsg', b'WWVoice',
                 b'magiccube', b'rtxapp', b'wework-file', b'wwmedia',
                 b'ext_info', b'msg.Voice', b'Voice.', b'.Voice',
                 b'cdn_url', b'cdnthumb', b'thumb_aeskey', b'longvoice',
                 b'sfsurl', b'downloadurl']

for fp in files:
    data = fp.read_bytes()
    hits_cdn = list(CDN_RE.finditer(data))
    hits_media = []
    for m in MEDIA_MARKERS:
        p = 0
        while True:
            p = data.find(m, p)
            if p < 0: break
            hits_media.append((p, m.decode('latin-1', errors='replace')))
            p += 1
    if not hits_cdn and not hits_media: continue
    print(f'{"="*76}\n{fp.name}   (size={len(data)})')
    if hits_cdn:
        print('  ── CDN URL 匹配 ──')
        for m in hits_cdn[:10]:
            piece = m.group().decode('latin-1', errors='replace')
            print(f'    @+{m.start():#06x}  {piece[:250]!r}')
    if hits_media:
        print('  ── media markers ──')
        seen = {}
        for off, mk in hits_media:
            seen.setdefault(mk, []).append(off)
        for mk, offs in seen.items():
            ctx0 = data[max(0,offs[0]-16):offs[0]+len(mk.encode())+64]
            print(f'    {mk!r:>22}  ×{len(offs):<3} first@{offs[0]:#06x}  ctx={ctx0.hex()[:180]}')

print('\n[done]')
