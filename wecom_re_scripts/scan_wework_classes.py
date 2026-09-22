# scan_wework_classes.py — 扫 WXWork 全内存找 "class wework::" 开头的字符串
# 目标：定位 ForwardMessage 相关的 Task/Job 类
import ctypes, ctypes.wintypes as wt, subprocess, sys, re
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
h = k32.OpenProcess(0x0410, False, pid)

# 64 位 Python 查询 32 位进程走 VirtualQueryEx64，MBI64 结构
class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_ulonglong),
                ('AllocationBase', ctypes.c_ulonglong),
                ('AllocationProtect', wt.DWORD),
                ('__a1', wt.DWORD),
                ('RegionSize', ctypes.c_ulonglong),
                ('State', wt.DWORD),
                ('Protect', wt.DWORD),
                ('Type', wt.DWORD),
                ('__a2', wt.DWORD)]

def rpm(addr, n):
    buf = (ctypes.c_ubyte * n)()
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    return bytes(buf[:read.value]) if ok else b''

# 枚举可读区域
regions = []
addr = 0
mbi = MBI()
while addr < 0x80000000:
    ret = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not ret: break
    if mbi.State == 0x1000 and (mbi.Protect & 0xff) in (0x02, 0x04, 0x20, 0x40, 0x80):
        # readable
        if mbi.RegionSize < 64 * 1024 * 1024:  # 跳过 >64MB 巨型 region
            regions.append((mbi.BaseAddress, mbi.RegionSize))
    addr = mbi.BaseAddress + mbi.RegionSize

print(f'regions to scan: {len(regions)}')

# 搜索 "class wework::"
NEEDLE = b'class wework::'
hits = []
scanned_mb = 0
for base, size in regions:
    if scanned_mb > 4096: break  # 上限 4GB
    try:
        chunk = rpm(base, min(size, 4 * 1024 * 1024))
    except:
        continue
    if not chunk: continue
    scanned_mb += len(chunk) // (1024*1024)
    idx = 0
    while True:
        p = chunk.find(NEEDLE, idx)
        if p < 0: break
        # 读到 \x00
        end = chunk.find(b'\x00', p, p+256)
        if end < 0: end = p + 256
        s = chunk[p:end].decode('ascii', errors='replace')
        hits.append((base + p, s))
        idx = end + 1
    # 若 region 大于 4MB，只扫前 4MB（性能）

print(f'\n[总命中] {len(hits)} 处 class wework::* 字符串')
uniq = Counter(s for _, s in hits)
print(f'唯一类名: {len(uniq)}\n')

# 只显示含关键字的类
KEYS = ['Forward', 'Send', 'Message', 'Transmit', 'Relay', 'Repeat']
for key in KEYS:
    print(f'--- 含 "{key}" ---')
    for s, n in uniq.most_common():
        if key in s:
            print(f'  x{n}: {s}')
    print()

# 保存全量
out = OUT / 'wework_classes_all.txt'
with out.open('w', encoding='utf-8') as f:
    for s, n in uniq.most_common():
        f.write(f'{n}\t{s}\n')
print(f'[+] {out}')
k32.CloseHandle(h)
