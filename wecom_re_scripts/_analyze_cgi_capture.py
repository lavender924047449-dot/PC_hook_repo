import json, sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = sorted(Path(__file__).parent.glob('cgi_capture_*.ndjson'))[-1]
lines = p.read_text(encoding='utf-8').strip().splitlines()
print(f'file={p.name} captures={len(lines)}')

def decode_pb(data, max_fields=20):
    out, i = [], 0
    while i < len(data) and len(out) < max_fields:
        b = data[i]; i += 1
        if b == 0: break
        field, wire = b >> 3, b & 7
        if field == 0 or field > 500: break
        if wire == 0:
            v = s = 0
            while i < len(data):
                vb = data[i]; i += 1
                v |= (vb & 0x7f) << s; s += 7
                if not (vb & 0x80): break
            out.append((field, 'varint', v))
        elif wire == 2:
            ln = s = 0
            while i < len(data):
                vb = data[i]; i += 1
                ln |= (vb & 0x7f) << s; s += 7
                if not (vb & 0x80): break
            if ln < 0 or ln > 65536 or i + ln > len(data): break
            payload = data[i:i+ln]; i += ln
            try:
                txt = payload.decode('utf-8')
                out.append((field, 'str', txt))
            except Exception:
                out.append((field, 'bytes', payload.hex()[:120]))
        else:
            break
    return out

for idx, line in enumerate(lines, 1):
    cap = json.loads(line)
    print(f'\n=== CAP {idx} ts={cap["ts"]} ===')
    for h in cap.get('hits', []):
        print(f'  arg{h["arg"]} @ {h["addr"]} URL={h["hasURL"]} CGI={h["hasCGI"]}')
        for s in h.get('strings', [])[:8]:
            print(f'    +{s["off"]:3d}: {s["s"][:120]}')
        for addr, info in h.get('ptrs', {}).items():
            for ss in info.get('strings', []):
                t = ss['s']
                if t.startswith('S:') or 'conversation' in t.lower() or 'ClientId' in t or 'msgId' in t:
                    print(f'    ptr 0x{addr}: {t[:100]}')
            hx = info.get('hex256', '')
            if not hx: continue
            bs = bytes.fromhex(hx)
            if bs and (bs[0] & 7) <= 2 and (bs[0] >> 3) > 0:
                pb = decode_pb(bs)
                if len(pb) >= 3:
                    print(f'    proto-candidate 0x{addr}: {pb[:8]}')
