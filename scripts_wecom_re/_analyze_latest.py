import json, pathlib, sys

def analyze(fname):
    p = pathlib.Path(fname)
    if not p.exists():
        print(f"NOT FOUND: {fname}")
        return
    data = json.loads(p.read_text(encoding='utf-8'))
    print(f"=== {p.name} ===")
    print(f"event_count: {data.get('event_count')}, pid: {data.get('pid')}")
    events = data.get('events', [])
    for i, ev in enumerate(events[:3]):
        print(f"--- event {i} ---")
        print(f"  ret: {ev.get('ret')}")
        print(f"  path: {ev.get('path','')[:80]}")
        print(f"  sql: {ev.get('sql','')[:120]}")
        frames = ev.get('frames', [])
        for f in frames[:6]:
            fr = f.get('ret','')
            args = f.get('args', [])
            print(f"  frame[{f['i']}] ret={fr}")
            for a in args:
                s8 = a.get('s8','')[:40]
                u64 = a.get('u64')
                u64dec = u64['dec'] if u64 else ''
                print(f"    off={a['off']} hex={a['hex']} u32={a['u32']} s8={repr(s8)} u64dec={u64dec}")
        after = ev.get('after_sql', [])
        if after:
            print(f"  after_sql (first 16 slots):")
            for a in after[:16]:
                s8 = a.get('s8','')[:30]
                u64 = a.get('u64')
                u64dec = u64['dec'] if u64 else ''
                print(f"    off={a['off']} hex={a['hex']} u32={a['u32']} u64dec={u64dec} s8={repr(s8)}")

files = [
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_bind_deep_20632_safe_120s_followup2.json",
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_bind_deep_20632_safe_90s_followup5.json",
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_postcall_conditional_21180_140s.json",
]

for f in files:
    analyze(f)
    print()
