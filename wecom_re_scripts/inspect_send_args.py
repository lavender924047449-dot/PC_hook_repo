# inspect_send_args.py — 读 hit 时栈参数指向的对象内容（std::string / SessionCtx / etc.）
import ctypes, ctypes.wintypes as wt, subprocess, sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

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

def rpm(a, n):
    buf = (ctypes.c_ubyte * n)()
    rd = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(a), buf, n, ctypes.byref(rd))
    return bytes(buf[:rd.value]) if ok else b''

# Hit #1 的栈参数
STACK_ARGS = {
    'ret_addr': 0x006bbf6c,
    'arg1@esp+04': 0xcbad4fa8,     # 疑似 sentinel
    'arg3@esp+0c': 0x35774700,
    'arg4@esp+10': 0x16db7c10,
    'arg5@esp+14': 0x25d833d0,
    'arg7@esp+1c': 0xcbad4fa8,     # 同 arg1
    'arg8@esp+20': 0x17fdf1ac,     # stack local
    'arg9@esp+24': 0x09ef211d,     # code addr
}

def dump_obj(addr, label, n=128):
    data = rpm(addr, n)
    if not data:
        print(f'\n  {label} @ 0x{addr:08x}  [!] unreadable')
        return
    print(f'\n  === {label} @ 0x{addr:08x} ===')
    for j in range(0, len(data), 32):
        seg = data[j:j+32]
        asc = ''.join(chr(x) if 32<=x<127 else '.' for x in seg)
        print(f'    [+{j:03d}] {seg.hex()} | {asc}')
    # 如果前 4 字节是指针，deref 看看
    if len(data) >= 4:
        p = struct.unpack_from('<I', data, 0)[0]
        if 0x10000 < p < 0x80000000:
            sub = rpm(p, 64)
            if sub:
                asc = ''.join(chr(x) if 32<=x<127 else '.' for x in sub)
                print(f'    *[+0]=0x{p:08x} → {sub.hex()} | {asc}')

for label, addr in STACK_ARGS.items():
    if addr < 0x10000 or addr >= 0x80000000:
        print(f'\n  {label} = 0x{addr:08x}  [skip - not user-space ptr]')
        continue
    dump_obj(addr, label)

k32.CloseHandle(h)
