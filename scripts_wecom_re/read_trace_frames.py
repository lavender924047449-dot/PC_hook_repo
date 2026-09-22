import json, pathlib

f = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\message_lookup_any_query_trace_20632_120s_followup8.json')
data = json.loads(f.read_text(encoding='utf-8'))
print('event_count:', data.get('event_count'))
events = data.get('events', [])
print('First 3 events:')
for i, ev in enumerate(events[:3]):
    sql = ev.get('sql', '')[:80]
    print(f'  event[{i}] sql={sql}')
    frames = ev.get('frames', [])
    print(f'  frames({len(frames)}):')
    for fr in frames[:12]:
        ret = fr.get('ret', '')
        args = fr.get('args', [])
        print(f'    frame[{fr["i"]}] ret={ret}')
        for a in args[:4]:
            s8 = a.get('s8', '')[:40]
            print(f'      off={a["off"]} hex={a["hex"]} s8={repr(s8)}')
