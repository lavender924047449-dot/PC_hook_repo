# _g1_analyze_step1.py — 分析 Step 1 dump 里的 voice MessageObject，提取 G1 Step 3 所需字段
#
# 目的：
#   1. 逐 vtable 扫最有希望的候选 (voice_id / rtxapp / .silk / aeskey / file_id / duration)
#   2. 输出：每个候选 bin 里 ASCII 字符串 + proto 字段扫描 + 高熵 16B 块
#   3. 为 Step 3 生成 G1_INJECT_MAP 建议（offset + hex payload）

import sys, re, struct, json
from pathlib import Path
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_153937'

# 候选 vtable 优先级（先看 marker 报警的，再看已知 recv-voice family）
PRIORITY_VT = [
    ('0b9bccf4', 'voice_id marker ★★★'),    # hits=64
    ('0bdfebb8', 'rtxapp marker'),            # hits=37
    ('0ba8edc8', 'known recv-voice §47.15'),  # hits=3
    ('0b097b84', 'top-hits #1 unknown'),       # hits=74
    ('0b98b800', 'high-hits unknown'),         # hits=28
    ('0ba3e568', 'medium unknown'),            # hits=14
    ('0b986d44', 'medium unknown'),            # hits=11
]

VOICE_MARKERS = [
    b'.silk', b'.amr', b'SILK', b'#!SILK', b'aeskey', b'silk_url',
    b'voice_length', b'voiceid', b'voice_id', b'file_id', b'fileid',
    b'vfid', b'file_size', b'filesize', b'duration', b'msg.Voice',
    b'AudioMsg', b'silkmd5', b'md5', b'mediaid', b'cdn_key', b'cdnkey',
    b'MessageBody', b'RichMessage', b'ConvMessage', b'VoiceTextInfo',
    b'rtxapp', b'wework', b'.qq.com', b'wxwork', b'tencent',
]

def read_varint(data, off):
    v = 0; shift = 0
    for i in range(10):
        if off + i >= len(data): return None, 0
        b = data[off + i]
        v |= (b & 0x7f) << shift
        if b < 0x80: return v, i + 1
        shift += 7
    return None, 0

def proto_scan(data, max_fields=80, max_off=None):
    out = []; off = 0
    limit = max_off if max_off else len(data)
    while off < limit and len(out) < max_fields:
        tag_val, tl = read_varint(data, off)
        if tag_val is None or tl == 0: break
        field_num = tag_val >> 3
        wire = tag_val & 7
        if field_num == 0 or field_num > 5000: break
        entry = {'off': off, 'field': field_num, 'wire': wire}
        if wire == 0:
            v, l = read_varint(data, off + tl)
            if v is None: break
            entry['value'] = v
            off += tl + l
        elif wire == 1:
            if off + tl + 8 > len(data): break
            entry['value'] = struct.unpack('<Q', data[off+tl:off+tl+8])[0]
            off += tl + 8
        elif wire == 2:
            ln, ll = read_varint(data, off + tl)
            if ln is None or ln > 65536 or ln < 0: break
            if off + tl + ll + ln > len(data): break
            payload = data[off+tl+ll:off+tl+ll+ln]
            entry['len'] = ln
            entry['payload_off'] = off + tl + ll
            try:
                if all(0x09 <= b < 0x7f or b in (0x0a, 0x0d) for b in payload):
                    entry['type'] = 'string'
                    entry['value'] = payload.decode('utf-8', errors='replace')[:200]
                else:
                    raise UnicodeDecodeError('', b'', 0, 0, '')
            except UnicodeDecodeError:
                entry['type'] = 'bytes'
                entry['value'] = payload[:64].hex() + ('...' if ln > 64 else '')
            off += tl + ll + ln
        elif wire == 5:
            if off + tl + 4 > len(data): break
            entry['value'] = struct.unpack('<I', data[off+tl:off+tl+4])[0]
            off += tl + 4
        else:
            break
        out.append(entry)
    return out, off

def find_markers(data):
    found = []
    for m in VOICE_MARKERS:
        p = 0
        while True:
            p = data.find(m, p)
            if p < 0: break
            found.append({'marker': m.decode('latin-1'), 'off': p,
                          'ctx': data[max(0,p-4):p+len(m)+80].hex()})
            p += 1
    return found

def high_entropy(data, blocklen=16, uniq_min=12):
    out = []
    for off in range(0, len(data)-blocklen, 4):
        chunk = data[off:off+blocklen]
        if len(set(chunk)) < uniq_min: continue
        if all(0x20 <= b < 0x7f for b in chunk): continue
        if chunk.count(0) > 2: continue
        out.append({'off': off, 'hex': chunk.hex()})
        if len(out) >= 20: break
    return out

def truncate_tail(data):
    tail = len(data)
    while tail > 0 and data[tail-1] == 0: tail -= 1
    return tail

report = {}

for vt, label in PRIORITY_VT:
    files = sorted(OUT_DIR.glob(f'voice_recv_{TS}_vt{vt}_n*_arg0.bin'))
    if not files:
        print(f'[SKIP] vt=0x{vt}  ({label})  no files')
        continue
    print(f'\n{"="*80}')
    print(f'▼▼ vt=0x{vt}  [{label}]  files={len(files)}')
    print(f'{"="*80}')
    vt_entries = []
    for fp in files[:3]:  # 最多看 3 个样本
        data = fp.read_bytes()
        tail = truncate_tail(data)
        print(f'\n--- {fp.name}  size={len(data)}  non-zero-tail={tail}')
        # markers
        marks = find_markers(data[:tail if tail>0 else len(data)])
        if marks:
            print(f'  ★ markers ({len(marks)}):')
            for m in marks[:20]:
                print(f'    @+0x{m["off"]:04x}  {m["marker"]!r}  ctx={m["ctx"][:120]}')
        # 前 64B hex
        print(f'  header 64B:')
        for i in range(0, min(64, tail), 16):
            chunk = data[i:i+16]
            hexs = ' '.join(f'{b:02x}' for b in chunk)
            ascs = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
            print(f'    +{i:04x}  {hexs:<48}  {ascs}')
        # proto scan（从 0 起）
        entries, consumed = proto_scan(data, max_off=tail if tail>0 else 512)
        if entries:
            print(f'  proto (consumed {consumed} / {tail} B, {len(entries)} fields):')
            for e in entries[:30]:
                tag = f'#{e["field"]:>3}/w{e["wire"]}'
                if e['wire'] == 2:
                    val = str(e.get('value',''))[:120]
                    p_off = e.get('payload_off', '?')
                    print(f'    @+{e["off"]:04x}  {tag}  len={e.get("len",0):>4}  {e.get("type","?"):>6}  '
                          f'payload@+{p_off}   {val!r}')
                else:
                    v = e.get('value', 0)
                    print(f'    @+{e["off"]:04x}  {tag}  value={v}  (0x{v:x})')
        # 高熵
        he = high_entropy(data[:tail if tail>0 else 512])
        if he:
            print(f'  high-entropy 16B blocks (aeskey/md5 候选):')
            for h in he[:6]:
                print(f'    @+0x{h["off"]:04x}  {h["hex"]}')
        vt_entries.append({'file': fp.name, 'size': len(data), 'tail': tail,
                           'marker_cnt': len(marks), 'proto_fields': len(entries)})
    report[vt] = {'label': label, 'entries': vt_entries}

# 汇总输出
print(f'\n\n{"="*80}\n★ 汇总（G1 Step 3 候选打分）\n{"="*80}')
for vt, info in report.items():
    total_marks = sum(e['marker_cnt'] for e in info['entries'])
    total_proto = sum(e['proto_fields'] for e in info['entries'])
    print(f'  vt=0x{vt}  [{info["label"][:30]:>30}]  markers={total_marks:>3}  proto_fields={total_proto:>3}')

# 落盘
(OUT_DIR / f'_g1_step1_analysis.json').write_text(
    json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[done] report saved: _g1_step1_analysis.json')
