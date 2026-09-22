import json, pathlib

files = [
    r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\postcall_20632_run2.json',
    r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_bind_deep_20632_safe_90s_followup5.json',
]

for fn in files:
    f = pathlib.Path(fn)
    print(f'=== {f.name} ===')
    try:
        data = json.loads(f.read_text(encoding='utf-8'))
        print(f'  events: {data.get("event_count")} pid={data.get("pid")}')
        events = data.get('events', [])
        for i, ev in enumerate(events):
            print(f'  event[{i}]:')
            # print all keys
            for k, v in ev.items():
                if k in ('frames', 'after_sql', 'struct', 'slots', 'dump'):
                    if isinstance(v, list):
                        print(f'    {k}: ({len(v)} items)')
                        for item in v[:20]:
                            print(f'      {item}')
                    elif isinstance(v, str):
                        print(f'    {k}: {v[:200]}')
                    else:
                        print(f'    {k}: {v}')
                else:
                    val = str(v)[:100]
                    print(f'    {k}: {val}')
    except Exception as e:
        print(f'  ERROR: {e}')
    print()
