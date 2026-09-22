# scan_session_ids.py — 全内存扫 "S:1688855042791155_" 会话 ID 字符串
# 每个命中位置 dump 前后 128B 上下文（找 msg_id / seq / class_name / dest_conv）
import ctypes, ctypes.wintypes as wt, subprocess, sys, re, struct
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
h = k32.OpenProcess(0x0410, False, pid)

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_ulonglong),
                ('AllocationBase', ctypes.c_ulonglong),
                ('AllocationProtect', wt.DWORD), ('__a1', wt.DWORD),
                ('RegionSize', ctypes.c_ulonglong),
                ('State', wt.DWORD), ('Protect', wt.DWORD),
                ('Type', wt.DWORD), ('__a2', wt.DWORD)]

def rpm(a, n):
    buf = (ctypes.c_ubyte * n)()
    rd = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n, ctypes.byref(rd))
    return bytes(buf[:rd.value]) if ok else b''

# 枚举可读堆区
regions = []
addr = 0
mbi = MBI()
while addr < 0x80000000:
    ret = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not ret: break
    base = int(mbi.BaseAddress); size = int(mbi.RegionSize)
    if mbi.State == 0x1000 and (mbi.Protect & 0xff) in (0x02, 0x04, 0x20, 0x40, 0x80):
        if int(mbi.Type) == 0x20000 and size < 64*1024*1024:  # MEM_PRIVATE
            regions.append((base, size))
    addr = base + size

# 扫的字符串（多种前缀 & UTF-16 情况都考虑）
NEEDLES = [
    b'S:1688855042791155_',   # ANSI 版本
]

session_hits = []  # (addr, ansi_str, context_before, context_after)
for base, size in regions:
    data = rpm(base, min(size, 16*1024*1024))
    if not data: continue
    for needle in NEEDLES:
        idx = 0
        while True:
            p = data.find(needle, idx)
            if p < 0: break
            # 读到 '\0' 或非 ASCII
            end = p
            while end < len(data) and 32 <= data[end] < 127:
                end += 1
            s = data[p:end].decode('ascii', errors='replace')
            session_hits.append((base + p, s))
            idx = end + 1

print(f'\n[命中] S:1688855042791155_* 字符串: {len(session_hits)} 处')
uniq = Counter(s for _, s in session_hits)
print(f'唯一 session/msg id: {len(uniq)}\n')

# 打印所有唯一 id + 出现次数
for s, n in uniq.most_common(30):
    print(f'  x{n}: {s}')

# 抽 3 个不同 session 看上下文
seen = set()
sampled = []
for addr, s in session_hits:
    if s in seen: continue
    seen.add(s)
    sampled.append((addr, s))
    if len(sampled) >= 5: break

print('\n' + '='*70)
print('样本上下文（各 session_id 附近 256B 前 + 256B 后）:')
print('='*70)
for addr, s in sampled:
    print(f'\n>>> {s} @ 0x{addr:08x}')
    ctx = rpm(addr - 128, 512)
    if not ctx: continue
    for j in range(0, len(ctx), 32):
        seg = ctx[j:j+32]
        asc = ''.join(chr(x) if 32<=x<127 else '.' for x in seg)
        marker = ' ← STR' if (j >= 128 and j < 128 + len(s)) else ''
        print(f'  0x{addr-128+j:08x}  {seg.hex()} | {asc}{marker}')

# 保存
out = OUT / 'session_ids_scan.txt'
with out.open('w', encoding='utf-8') as f:
    f.write(f'PID={pid}\ntotal={len(session_hits)}  unique={len(uniq)}\n\n')
    for s, n in uniq.most_common():
        f.write(f'{n}\t{s}\n')
print(f'\n[+] {out}')
k32.CloseHandle(h)
