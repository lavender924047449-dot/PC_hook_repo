# inspect_task_str_ctx.py — 查看 PostSendMessageTask2 字符串前后 256 字节上下文
# 目的：判断它是"注册表条目"还是"编译器孤立字符串"
import ctypes, ctypes.wintypes as wt, subprocess, sys, struct
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

def dump(b, base_addr, label=''):
    print(f'\n  --- {label} @ 0x{base_addr:08x} ---')
    for j in range(0, len(b), 32):
        seg = b[j:j+32]
        ascii_s = ''.join(chr(x) if 32<=x<127 else '.' for x in seg)
        print(f'    0x{base_addr+j:08x}  {seg.hex()} | {ascii_s}')

TARGETS = {
    'PostSendMessageTask2 #1': 0x26252aac,
    'PostSendMessageTask2 #2': 0x389a07c8,
    'InitMessageSenderLookupTask': 0x2641ccd4,
    'TimerUpdateMessageTimeTask #1': 0x2615ad48,
    'SetGlobalItemsTask (already known)': 0x35764e04,
}

for label, addr in TARGETS.items():
    print(f'\n{"="*70}\n{label}  addr=0x{addr:08x}\n{"="*70}')
    # 前 128 字节 + 后 128 字节
    pre = rpm(addr - 128, 128)
    at  = rpm(addr, 256)
    if not pre or not at:
        print('  [!] read failed'); continue
    dump(pre, addr - 128, 'BEFORE (-128..0)')
    dump(at, addr, 'STRING itself + AFTER')

    # 前 128 字节里找 4 字节值 = addr 或 addr+1..+8 的（说明是被"pointer + inline-string" 引用）
    print(f'\n  [analysis] 前 128B 中指向此字符串的 32-bit 值:')
    for i in range(0, len(pre) - 4, 4):
        v = struct.unpack_from('<I', pre, i)[0]
        if addr <= v <= addr + 8:
            print(f'    offset -{128-i}: 0x{v:08x} (= addr+{v-addr})')

k32.CloseHandle(h)
