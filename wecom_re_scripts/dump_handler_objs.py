# dump_handler_objs.py — 用 ReadProcessMemory 读 3 个 handler ptr + task 里潜在指针指向的对象
import ctypes, ctypes.wintypes as wt, subprocess, sys, json, struct
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('no pid')

pid = get_pid()
print(f'PID={pid}')

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
if not h:
    print('OpenProcess failed'); sys.exit(1)

def rpm(addr, n):
    buf = (ctypes.c_ubyte * n)()
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    if not ok: return None
    return bytes(buf[:read.value])

def u32(b, o):
    if o+4 > len(b): return None
    return b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)

def dump_hex(b, prefix='  '):
    for j in range(0, min(len(b), 256), 32):
        seg = b[j:j+32]
        ascii_s = ''.join(chr(x) if 32<=x<127 else '.' for x in seg)
        print(f'{prefix}[+{j:03d}] {seg.hex()} | {ascii_s}')

# 从 fwd_ab_v2 里取 3 个 handler ptr
target = sorted(OUT.glob('fwd_ab_v2_*.json'))[-1]
data = json.loads(target.read_text(encoding='utf-8'))
events = data['events']

# 每个 handler 下取一条 A、一条 B，dump handler ptr / task+4 ptr / task+16 ptr
handlers = sorted(set(e['handlerPtr'] for e in events))
print(f'handlers: {handlers}\n')

for h_hex in handlers:
    print('='*70)
    print(f'handler {h_hex}')
    print('='*70)
    hv = int(h_hex, 16)
    obj = rpm(hv, 256)
    if obj:
        # 首 4 字节是 vtable ptr
        vt = u32(obj, 0)
        print(f'  *handler[+0] (vtable) = 0x{vt:08x}')
        dump_hex(obj)
    else:
        print('  [!] read failed'); continue

    # 分 A/B 各一条：看 task 是否随 dest 变化
    for phase, name in [(2,'A→FTA'), (3,'B→外部')]:
        evs = [e for e in events if e['phase']==phase and e['handlerPtr']==h_hex]
        if not evs: continue
        e = evs[0]
        task = bytes(e['task'])
        print(f'\n  Round {name} begin={e["begin"]}')
        # 扫描 task 里所有 0x10000000+ 的 4 字节值（潜在指针）
        for off in range(0, len(task)-4, 4):
            v = u32(task, off)
            if v is None: continue
            if 0x10000000 <= v < 0x60000000:
                sub = rpm(v, 128)
                if sub:
                    print(f'    task+{off:03d} → 0x{v:08x}: [+0..32]={sub[:32].hex()}')

    # 同时看 handler ptr 指向对象在 A/B 时的当前内容对比
    # （只是一次快照，可能已过 handler 处理时刻）

k32.CloseHandle(h)
print('\ndone')
