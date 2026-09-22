import json, pathlib

p = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\message_lookup_any_query_trace_20632_120s_followup8.json')
d = json.loads(p.read_text('utf-8'))
print('events=', d.get('event_count'))
for i, ev in enumerate(d.get('events', [])):
    ret = ev.get('ret', '')
    s0 = ev.get('s0', '')[:80]
    print(f'--- ev {i} ret={ret} ---')
    print(f'  s0: {s0}')
    h1 = ev.get('h1', '')
    for line in h1.split('\n')[:6]:
        print('  h1:', line)
    bt = ev.get('bt', [])
    print('  bt0:', str(bt[0])[:80] if bt else '')
    print()
