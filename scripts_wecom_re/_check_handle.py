import json, pathlib

d = json.loads(pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\sqlite_handle_scan.json').read_text('utf-8'))
r = d['results'][0] if d['results'] else {}
print('sql_text_found_at:', r.get('sql_text_found_at'))
print('logger_hits:', r.get('logger_hits'))
print()
print('=== Static Candidates ===')
for c in r.get('static_candidates', []):
    addr = c['addr']
    valid = c['valid']
    hd = c.get('hd','')[:100]
    print(f'  {addr} valid={valid}')
    print(f'    hd: {hd}')
print()
print('=== Dynamic Handles ===')
for c in r.get('dynamic_handles', []):
    addr = c['addr']
    valid = c['valid']
    hd = c.get('hd','')[:120]
    print(f'  {addr} valid={valid}')
    print(f'    hd: {hd}')
