import json, pathlib

# 读取所有 trace 文件，找有 frames 的 event
trace_dir = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
files = sorted(trace_dir.glob('*.json'), key=lambda x: x.stat().st_mtime, reverse=True)

for f in files:
    try:
        data = json.loads(f.read_text(encoding='utf-8'))
        events = data.get('events', [])
        has_frames = any(e.get('frames') for e in events)
        has_sql = any(e.get('sql') for e in events)
        print(f'{f.name}: events={len(events)} has_frames={has_frames} has_sql={has_sql}')
        if has_frames:
            for i, ev in enumerate(events):
                frames = ev.get('frames', [])
                if frames:
                    print(f'  event[{i}]: sql={ev.get("sql","")[:60]}')
                    for fr in frames[:8]:
                        ret = fr.get('ret', '')
                        print(f'    frame[{fr["i"]}] ret={ret}')
                    break
            break
    except Exception as e:
        print(f'{f.name}: ERROR {e}')
