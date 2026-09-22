# _analyze_voice.py — 分析 voice_recon_*.bin 里的 arg0
#
# 目的：从 4 个 TOP-LEVEL vtable + 1 ExtraContent 的 dump 里
#   1. 提取全部 ASCII 字符串（≥4 字符）
#   2. 尝试按 protobuf wire 格式解析（varint tag + wire type）
#   3. 找到 CDN URL / file_id / aeskey / duration 等凭证字段
#   4. 输出按 vtable 分组的 summary

import sys, re, struct
from pathlib import Path
from collections import defaultdict

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_134435'

def extract_strings(data, min_len=4):
    return [(m.start(), m.group().decode('latin-1', errors='replace'))
            for m in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data)]

def read_varint(data, off):
    """returns (value, bytes_read)"""
    v = 0; shift = 0
    for i in range(10):
        if off + i >= len(data): return None, 0
        b = data[off + i]
        v |= (b & 0x7f) << shift
        if b < 0x80: return v, i + 1
        shift += 7
    return None, 0

def proto_scan(data, max_fields=60):
    """尝试按 proto wire format 解析。遇到不可解析就停。"""
    out = []
    off = 0
    while off < len(data) and len(out) < max_fields:
        tag_val, tl = read_varint(data, off)
        if tag_val is None or tl == 0: break
        field_num = tag_val >> 3
        wire = tag_val & 7
        if field_num == 0 or field_num > 5000: break
        entry = {'off': off, 'field': field_num, 'wire': wire}
        if wire == 0:  # varint
            v, l = read_varint(data, off + tl)
            if v is None: break
            entry['value'] = v
            off += tl + l
        elif wire == 1:  # 64-bit
            if off + tl + 8 > len(data): break
            entry['value'] = struct.unpack('<Q', data[off+tl:off+tl+8])[0]
            off += tl + 8
        elif wire == 2:  # length-delimited (bytes/string/nested)
            ln, ll = read_varint(data, off + tl)
            if ln is None or ln > 65536: break
            if off + tl + ll + ln > len(data): break
            payload = data[off+tl+ll:off+tl+ll+ln]
            entry['len'] = ln
            # 猜类型：全 ASCII → string
            try:
                s = payload.decode('utf-8')
                if all(0x09 <= b < 0x7f or b in (0x0a, 0x0d) for b in payload):
                    entry['type'] = 'string'
                    entry['value'] = s[:200]
                else:
                    raise UnicodeDecodeError('', b'', 0, 0, '')
            except UnicodeDecodeError:
                entry['type'] = 'bytes'
                entry['value'] = payload[:64].hex() + ('...' if ln > 64 else '')
            off += tl + ll + ln
        elif wire == 5:  # 32-bit
            if off + tl + 4 > len(data): break
            entry['value'] = struct.unpack('<I', data[off+tl:off+tl+4])[0]
            off += tl + 4
        else:
            break
        out.append(entry)
    return out, off

# 找到所有 arg0 dump 文件
files = sorted(OUT_DIR.glob(f'voice_recon_{TS}_h*_SER_vt*_arg0.bin'))
by_vt = defaultdict(list)
for fp in files:
    m = re.search(r'_vt([0-9a-f]+)_arg0', fp.name)
    if m:
        by_vt[m.group(1)].append(fp)

print(f'找到 {len(files)} 个 SER arg0 dump，按 vtable 分组：')
for vt, lst in by_vt.items():
    print(f'  vt=0x{vt}  ×{len(lst)}  {lst[0].name}')

# 也拉 presend arg0（4KB，是外层 send 参数）
presend_files = sorted(OUT_DIR.glob(f'voice_recon_{TS}_presend*_arg0.bin'))
print(f'\n找到 {len(presend_files)} 个 presend arg0 dump')

print('\n' + '='*80)
print('★ 逐 vtable 分析（只看每组第一个）')
print('='*80)

VT_LABEL = {
    'b0610c0': 'SER#1 — outer wrapper',
    'b06c9b8': 'SER#2 — sub-msg A',
    'b0656a8': 'SER#3/#4 — repeated field ★★★ (可能是 voice body!)',
    'b0901ac': 'SER#5 — ww_richmessage.ExtraContent (#00)',
}

for vt, lst in by_vt.items():
    print(f'\n\n{"="*80}\n▼▼▼ vt=0x{vt}  [{VT_LABEL.get(vt, "?")}]  file={lst[0].name}\n{"="*80}')
    data = lst[0].read_bytes()
    # 找有效 payload 长度（连续非 0 区）
    tail = len(data)
    while tail > 0 and data[tail-1] == 0: tail -= 1
    print(f'  size={len(data)}  non-zero-tail={tail}')

    # ASCII strings
    strs = extract_strings(data[:tail if tail > 64 else 256])
    if strs:
        print(f'\n  ── ASCII strings (≥4 chars) ──')
        for off, s in strs[:40]:
            print(f'    @+{off:04x}  {s!r}')

    # Proto scan
    entries, consumed = proto_scan(data[:tail if tail > 0 else len(data)])
    print(f'\n  ── proto scan (consumed {consumed} bytes, {len(entries)} fields) ──')
    for e in entries[:40]:
        tag = f'#{e["field"]:>3}/w{e["wire"]}'
        if e['wire'] == 2:
            print(f'    @+{e["off"]:04x}  {tag}  len={e.get("len","?"):>4}  {e.get("type","?"):>6}  {str(e.get("value",""))[:180]!r}')
        else:
            v = e.get('value', 0)
            print(f'    @+{e["off"]:04x}  {tag}  value={v}  (0x{v:x})')

    # Header hex (前 64 字节)
    print(f'\n  ── header 64B ──')
    for i in range(0, min(64, tail), 16):
        chunk = data[i:i+16]
        hexs = ' '.join(f'{b:02x}' for b in chunk)
        ascs = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        print(f'    +{i:04x}  {hexs:<48}  {ascs}')

# presend arg0 (取 #1)
if presend_files:
    fp = presend_files[0]
    data = fp.read_bytes()
    print(f'\n\n{"="*80}\n▼▼▼ PreSend arg0 (可能是 return buffer 或 arg struct)  file={fp.name}\n{"="*80}')
    tail = len(data)
    while tail > 0 and data[tail-1] == 0: tail -= 1
    print(f'  size={len(data)}  non-zero-tail={tail}')
    strs = extract_strings(data[:tail if tail > 64 else 256])
    if strs:
        print(f'  ── ASCII strings ──')
        for off, s in strs[:30]:
            print(f'    @+{off:04x}  {s!r}')

print('\n[done]')
