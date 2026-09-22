"""分析 post-call struct dump 结果，寻找 sequence/send_time"""
import json, pathlib, sys

def analyze(fname):
    p = pathlib.Path(fname)
    if not p.exists():
        print(f"NOT FOUND: {fname}")
        return
    data = json.loads(p.read_text(encoding='utf-8'))
    print(f"=== {p.name} ===")
    print(f"pid={data.get('pid')} event_count={data.get('event_count')}")
    
    events = data.get('events', [])
    for i, ev in enumerate(events):
        if 'frida_error' in ev:
            print(f"--- ev {i} ERROR: {ev['frida_error']} ---")
            continue
        
        gate = ev.get('gate', {})
        fa = ev.get('frame_args', {})
        
        print(f"--- ev {i} ts={ev.get('ts')} ---")
        print(f"  gate.path = {gate.get('path','')[:80]}")
        print(f"  gate.sql  = {gate.get('sql','')[:80]}")
        print(f"  frame_args: a8={fa.get('a8')} a12={fa.get('a12')} a16={fa.get('a16')} a20={fa.get('a20')} a24={fa.get('a24')} a28={fa.get('a28')}")
        
        # Analyze struct at a12
        struct = ev.get('struct_a12', [])
        print(f"  struct_a12 ({len(struct)} slots):")
        for slot in struct[:20]:
            off = slot.get('off')
            u32v = slot.get('u32')
            u64h = slot.get('u64_here')
            s8v = slot.get('s8', '')[:30]
            u64at = slot.get('u64_at')
            
            # Try to interpret
            interp = ''
            if u32v and 200_000_000 < u32v < 300_000_000:
                interp = f' ← possible msg_id ({u32v})'
            elif u64h and u64h.get('lo') and 200_000_000 < u64h['lo'] < 300_000_000:
                interp = f' ← possible msg_id (lo={u64h["lo"]})'
            elif u64h and 1_700_000_000 < (u64h.get('lo', 0) or 0) < 1_800_000_000:
                interp = f' ← possible timestamp_s (lo={u64h["lo"]})'
            elif u32v and 1 < u32v < 100_000:
                interp = f' ← small int (sequence?)'
            
            print(f"    off={off} dword={slot.get('hex')} u32={u32v}{interp}")
            if u64h:
                print(f"       u64_here={u64h.get('hex')} dec={u64h.get('dec')}")
        
        # Hex dump
        hd = ev.get('struct_a12_hd', '')
        print(f"  struct_a12_hd:")
        for line in hd.split('\n')[:12]:
            print(f"    {line}")
        
        # Regs
        regs = ev.get('regs', {})
        print(f"  regs: eax={regs.get('eax')} ebx={regs.get('ebx')} ecx={regs.get('ecx')} edx={regs.get('edx')}")
        print()

files = [
    r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\postcall_20632_run2.json",
]
for f in files:
    analyze(f)
