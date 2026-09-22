import json, sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('hook_frames_20260911_134321.json', 'r', encoding='utf-8') as f:
    caps = json.load(f)

# 找 f2_top captures 的 args
for i, cap in enumerate(caps):
    if cap.get('label') != 'f2_top': continue
    print(f'\n=== cap#{i} f2_top ===')
    # args
    args = cap.get('args', [])
    if not args:
        print('  (no args recorded)')
    else:
        print(f'  args count: {len(args)}')
        for j, a in enumerate(args[:8]):
            bs = bytes.fromhex(a.replace(' ','')) if isinstance(a, str) else b''
            if bs:
                # hex dump
                row = ' '.join(f'{b:02x}' for b in bs[:32])
                print(f'  args[{j}]: {row}')
                # ascii strings
                for m in re.finditer(rb'[\x20-\x7e]{5,}', bs):
                    s = m.group().decode('ascii')
                    print(f'    str[+0x{m.start():02x}]: {s[:80]}')
                # UTF-16LE
                try:
                    u16 = bs.decode('utf-16-le', errors='ignore')
                    for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{5,}', u16):
                        print(f'    u16[+0x{m.start()*2:02x}]: {m.group()[:80]}')
                except: pass
            else:
                print(f'  args[{j}]: {a}')

# 检查 args[1] 中的指针
print('\n=== args[1] 指针分析 (cap#2) ===')
import struct
cap2 = caps[2]  # 第一个 f2_top
a1 = cap2.get('args',[None])[1] if cap2.get('args') else None
if a1 and isinstance(a1, str):
    bs = bytes.fromhex(a1.replace(' ',''))
    print(f'a1 len: {len(bs)}B')
    for off in range(0, min(64, len(bs)), 4):
        v = struct.unpack_from('<I', bs, off)[0]
        if 0x1000000 < v < 0x7FFFFFFF:
            print(f'  a1[+0x{off:02x}] = 0x{v:08x} (potential pointer)')
else:
    print('no args[1]')
