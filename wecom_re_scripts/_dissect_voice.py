# _dissect_voice.py — 剖析 voice recv 关键 vtable 的 arg0/this
import re, struct
from pathlib import Path

OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
TS = '20260914_141437'
TARGETS = ['0b9c0620', '0b9c0244', '0ba8edc8', '0b98b800', '0b0834e4']

def read_varint(data, off):
    v = 0; shift = 0
    for i in range(10):
        if off + i >= len(data): return None, 0
        b = data[off + i]
        v |= (b & 0x7f) << shift
        if b < 0x80: return v, i + 1
        shift += 7
    return None, 0

def proto_scan(data, max_fields=80):
    out = []; off = 0
    while off < len(data) and len(out) < max_fields:
        tag_val, tl = read_varint(data, off)
        if tag_val is None or tl == 0: break
        field_num = tag_val >> 3; wire = tag_val & 7
        if field_num == 0 or field_num > 5000 or wire > 5 or wire in (3,4,6,7): break
        entry = {'off': off, 'field': field_num, 'wire': wire}
        if wire == 0:
            v, l = read_varint(data, off + tl)
            if v is None: break
            entry['value'] = v; off += tl + l
        elif wire == 1:
            if off + tl + 8 > len(data): break
            entry['value'] = struct.unpack('<Q', data[off+tl:off+tl+8])[0]; off += tl + 8
        elif wire == 2:
            ln, ll = read_varint(data, off + tl)
            if ln is None or ln > 262144: break
            if off + tl + ll + ln > len(data): break
            payload = data[off+tl+ll:off+tl+ll+ln]
            entry['len'] = ln
            try:
                s = payload.decode('utf-8')
                if all(0x09 <= b < 0x7f or b in (0x0a, 0x0d) for b in payload) and ln < 500:
                    entry['type'] = 'string'; entry['value'] = s[:300]
                else: raise UnicodeDecodeError('', b'', 0, 0, '')
            except UnicodeDecodeError:
                entry['type'] = 'bytes'
                entry['value'] = payload[:96].hex() + ('...' if ln > 96 else '')
            off += tl + ll + ln
        elif wire == 5:
            if off + tl + 4 > len(data): break
            entry['value'] = struct.unpack('<I', data[off+tl:off+tl+4])[0]; off += tl + 4
        out.append(entry)
    return out, off

def extract_strings(data, min_len=4):
    return [(m.start(), m.group().decode('latin-1', errors='replace'))
            for m in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data)]

for vt in TARGETS:
    print(f'\n{"█"*80}\n█ vt=0x{vt}\n{"█"*80}')
    for suffix in ['arg0', 'this']:
        files = sorted(OUT_DIR.glob(f'voice_recv_{TS}_vt{vt}_n*_{suffix}.bin'))
        for fp in files:
            data = fp.read_bytes()
            # 找非零 tail
            tail = len(data)
            while tail > 0 and data[tail-1] == 0: tail -= 1
            print(f'\n{"─"*76}\n▶ {fp.name}  size={len(data)}  non-zero-tail={tail}')

            # ASCII strings
            strs = extract_strings(data[:tail if tail > 32 else min(256, len(data))])
            if strs:
                print(f'  ── strings ({len(strs)}) ──')
                for off, s in strs[:35]:
                    print(f'    @+{off:04x}  {s[:180]!r}')

            # proto scan（从多个 offset 尝试）
            for start_off in (0, 1, 2, 4, 8, 12, 16, 20):
                if start_off >= tail: break
                entries, consumed = proto_scan(data[start_off:tail])
                if len(entries) >= 3:
                    print(f'  ── proto scan @+{start_off} (consumed {consumed}B, {len(entries)} fields) ──')
                    for e in entries[:30]:
                        tag = f'#{e["field"]:>3}/w{e["wire"]}'
                        if e['wire'] == 2:
                            print(f'    +{e["off"]+start_off:04x}  {tag}  len={e.get("len","?"):>5}  {e.get("type","?"):>6}  {str(e.get("value",""))[:200]!r}')
                        else:
                            v = e.get('value', 0)
                            print(f'    +{e["off"]+start_off:04x}  {tag}  value={v}  (0x{v:x})')
                    break

print('\n[done]')
