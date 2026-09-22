# find_send_log_xref.py — 找 "do send message to peer post to session" 格式串的 xref
# 目标：定位 WXWork.exe 代码段中所有 push/mov 该字符串地址的位置 → SendMessage 函数
import ctypes, ctypes.wintypes as wt, subprocess, sys, struct
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

# 关键格式串（尝试多种）
NEEDLES = [
    b'do send message to peer post to session conversationId = ',
    b'send message to peer callback conversationId = ',
    b',msgId = %d, ClientId: %s, task id = %d',
    b',msgId = ', 
    b'IsResendAsSecurityFile: ',
]

# Step 1: 找 WXWork.exe 的 .rdata / .text 范围
# WXWork.exe base = 0x2D0000, 大小 ~256MB
WX_BASE = 0x2D0000
WX_SIZE = 300 * 1024 * 1024

# 枚举 .exe module 的 region（Type = MEM_IMAGE = 0x1000000）
img_regions = []
addr = 0
mbi = MBI()
while addr < 0x80000000:
    ret = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not ret: break
    base = int(mbi.BaseAddress); size = int(mbi.RegionSize)
    if mbi.State == 0x1000 and int(mbi.Type) == 0x1000000:  # MEM_IMAGE
        prot = mbi.Protect & 0xff
        img_regions.append((base, size, prot))
    addr = base + size

wx_regions = [(b, s, p) for b, s, p in img_regions if WX_BASE <= b < WX_BASE + WX_SIZE]
print(f'WXWork.exe image regions: {len(wx_regions)}')
for b, s, p in wx_regions[:20]:
    prot_name = {0x02:'R', 0x04:'RW', 0x20:'RX', 0x40:'RWX', 0x80:'WCX'}.get(p, f'{p:x}')
    print(f'  0x{b:08x} +0x{s:08x}  prot={prot_name}')

# Step 2: 在 .rdata (只读区，通常 Protect=0x02) 里找字符串
str_addrs = {}
for needle in NEEDLES:
    str_addrs[needle] = []
for base, size, prot in wx_regions:
    if prot not in (0x02, 0x04):  # 只读/读写数据
        continue
    if size > 128 * 1024 * 1024: 
        # 分块读
        chunks = [(base + off, min(4*1024*1024, size - off)) for off in range(0, size, 4*1024*1024)]
    else:
        chunks = [(base, size)]
    for c_base, c_size in chunks:
        data = rpm(c_base, c_size)
        if not data: continue
        for needle in NEEDLES:
            idx = 0
            while True:
                p = data.find(needle, idx)
                if p < 0: break
                str_addrs[needle].append(c_base + p)
                idx = p + 1

print('\n[Step 2] .rdata 里的格式串地址:')
for needle, addrs in str_addrs.items():
    print(f'  {needle[:60]!r}: {len(addrs)} 处')
    for a in addrs[:3]:
        print(f'    0x{a:08x}')

# Step 3: 找 .text 段（Protect=0x20 RX）
text_regions = [(b, s) for b, s, p in wx_regions if p == 0x20]
print(f'\n[Step 3] .text 段: {len(text_regions)} 个 region')

# Step 4: 扫 .text 找指向格式串的 4 字节值（PUSH imm32 / MOV imm32）
# WXWork 是 32 位 x86，指令模式：
#   68 XX XX XX XX          PUSH imm32
#   B8/B9/BA/BB imm32        MOV eax/ecx/edx/ebx, imm32
#   C7 45 XX imm32           MOV DWORD PTR [ebp+XX], imm32
# 简单起见：找任意 4 字节值 == 格式串地址（对齐 = 任意）
key_needle = b'do send message to peer post to session conversationId = '
main_addrs = str_addrs.get(key_needle, [])
if not main_addrs:
    print(f'\n[!] 未找到关键格式串在 .rdata，改扫 heap 缓存里的地址')
    # 用之前 heap 里的 0x25b582c9
    main_addrs = [0x25b582c9]

print(f'\n[Step 4] 扫 .text 找 xref 目标: {[hex(a) for a in main_addrs]}')
xref_hits = []
for tb, ts in text_regions:
    # 分块 4MB
    for off in range(0, ts, 4*1024*1024):
        chunk_size = min(4*1024*1024, ts - off)
        data = rpm(tb + off, chunk_size)
        if not data: continue
        for target in main_addrs:
            # 4 字节小端匹配（unaligned）
            packed = struct.pack('<I', target)
            idx = 0
            while True:
                p = data.find(packed, idx)
                if p < 0: break
                # 判断是不是 PUSH imm32 (68 XX ...) 或 MOV
                addr = tb + off + p
                prev = data[max(0,p-1):p+5]
                xref_hits.append((addr, target, prev.hex()))
                idx = p + 1

print(f'\n[命中] .text 中 xref: {len(xref_hits)} 处')
for addr, tgt, ctx in xref_hits[:30]:
    print(f'  0x{addr:08x}  target=0x{tgt:08x}  ctx={ctx}')

# 保存
out = OUT / 'send_log_xref.txt'
with out.open('w', encoding='utf-8') as f:
    f.write(f'PID={pid}\n')
    for needle, addrs in str_addrs.items():
        f.write(f'\n{needle!r}: {len(addrs)}\n')
        for a in addrs: f.write(f'  0x{a:08x}\n')
    f.write(f'\nxref hits: {len(xref_hits)}\n')
    for addr, tgt, ctx in xref_hits:
        f.write(f'  0x{addr:08x}  target=0x{tgt:08x}  ctx={ctx}\n')
print(f'\n[+] {out}')
k32.CloseHandle(h)
