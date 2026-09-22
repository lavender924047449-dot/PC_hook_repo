# find_func_entry.py — 从 0x02E6566B 向上回溯，找函数入口序言 (55 8B EC / 53 8B DC / 6A FF 68)
# 输出候选入口地址，供 Frida hook
import ctypes, ctypes.wintypes as wt, subprocess, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.OpenProcess.restype = wt.HANDLE
h = k32.OpenProcess(0x0410, False, pid)

def rpm(a, n):
    buf = (ctypes.c_ubyte * n)()
    rd = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n, ctypes.byref(rd))
    return bytes(buf[:rd.value]) if ok else b''

TARGET = 0x02E6566B      # PUSH 格式串指令位置
LOOK_BACK = 0x2000       # 向前搜 8KB

# 从 TARGET - LOOK_BACK 到 TARGET，找函数入口序言
start = TARGET - LOOK_BACK
data = rpm(start, LOOK_BACK + 16)
if not data:
    print('[!] read failed'); exit(1)

# 常见 x86 函数序言字节序列
PROLOGUES = [
    (b'\x55\x8b\xec', 'PUSH EBP; MOV EBP, ESP'),           # stdcall/cdecl
    (b'\x53\x8b\xdc', 'PUSH EBX; MOV EBX, ESP'),           # WXWork 常见变体
    (b'\x6a\xff\x68', 'PUSH -1; PUSH imm32 (SEH prologue)'),
    (b'\x55\x89\xe5', 'PUSH EBP; MOV EBP, ESP (AT&T)'),
    (b'\x8b\xff\x55\x8b\xec', 'MOV EDI,EDI; PUSH EBP; MOV EBP,ESP (hotpatch)'),
]

# 找所有出现位置
print(f'[+] 从 0x{start:08x} 到 0x{TARGET:08x} 搜索序言')
candidates = []
for prol, desc in PROLOGUES:
    idx = 0
    while True:
        p = data.find(prol, idx)
        if p < 0 or p >= LOOK_BACK: break
        abs_addr = start + p
        # 前一字节应该是 return / jump / align (CC / C3 / C2 / 90 / EB / E9)
        prev = data[p-1] if p > 0 else 0
        aligned = (abs_addr & 0xf) == 0  # 常见对齐
        int3_prev = prev == 0xcc
        good = int3_prev or prev in (0xc3, 0xc2, 0x90, 0xeb, 0xe9) or aligned
        candidates.append((abs_addr, desc, good, prev))
        idx = p + 1

# 只保留距离 TARGET 最近的合理入口（good=True）
print(f'\n[候选序言] 全部 {len(candidates)} 处 (按接近 TARGET 排序):')
candidates.sort(key=lambda x: -x[0])  # 从近到远
for i, (addr, desc, good, prev) in enumerate(candidates[:20]):
    dist = TARGET - addr
    marker = '  ★' if good else '   '
    print(f'{marker} 0x{addr:08x}  (dist=+0x{dist:x})  prev=0x{prev:02x}  [{desc}]')

# 挑最近的 3 个 good 候选打印其上下文
print(f'\n[Top 3 good 候选函数首字节 dump]:')
good_list = [c for c in candidates if c[2]]
for addr, desc, good, prev in good_list[:5]:
    print(f'\n  === 0x{addr:08x} ({desc}) ===')
    off = addr - start
    ctx = data[max(0,off-4):off+32]
    ascii_s = ''.join(chr(x) if 32<=x<127 else '.' for x in ctx)
    print(f'    prev-4: {data[max(0,off-4):off].hex()}')
    print(f'    entry : {ctx[4:].hex()}')
    print(f'    ascii : {ascii_s}')

k32.CloseHandle(h)
