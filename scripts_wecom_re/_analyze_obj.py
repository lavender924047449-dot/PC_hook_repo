"""分析 lookup_object_dump 数据，找 sequence/send_time 字段偏移"""
import json, pathlib, sys

def analyze_obj(fname):
    p = pathlib.Path(fname)
    if not p.exists():
        print(f"NOT FOUND: {fname}"); return
    data = json.loads(p.read_text(encoding='utf-8'))
    print(f"=== {p.name} ===")
    print(f"event_count: {data.get('event_count')}")
    events = data.get('events', [])
    for i, ev in enumerate(events[:5]):
        print(f"--- event {i} ---")
        print(f"  ret: {ev.get('ret')}")
        print(f"  ts: {ev.get('ts')}")
        # object dump style
        obj = ev.get('obj_dump', ev.get('out_blob_from_esp_c', []))
        if obj:
            print(f"  obj_dump ({len(obj)} slots):")
            for slot in obj[:32]:
                off = slot.get('off', slot.get('offset', '?'))
                u64 = slot.get('u64') or slot.get('qword')
                u64dec = ''
                if u64:
                    u64dec = u64.get('dec', '') if isinstance(u64, dict) else str(u64)
                dword = slot.get('dword_hex', slot.get('hex', '?'))
                u32v = slot.get('u32', '?')
                print(f"    off={off} dword={dword} u32={u32v} u64dec={u64dec}")
        else:
            # fall back to other keys
            for k, v in ev.items():
                if k not in ('ts','ret','path','sql','frames','regs','h0','gate','tid','post_addr','stack_args','ebp_slots','esp_hd','error'):
                    print(f"  {k}: {str(v)[:200]}")

files = [
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_object_dump_9148_75s.json",
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_object_dump_24404_reopen_180s.json",
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_object_dump_26232_120s_after_send.json",
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\lookup_object_dump_13396_after_send_150s.json",
]
for f in files:
    analyze_obj(f)
    print()
