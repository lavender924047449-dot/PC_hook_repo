# find_task_objects.py — 定位 Task 类名字符串地址 → 反向扫全内存找指向它的对象实例
# 目标：找到 PostSendMessageTask2 / InitMessageSenderLookupTask 的对象实例
import ctypes, ctypes.wintypes as wt, subprocess, sys, struct, json
from pathlib import Path
from collections import defaultdict

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

def rpm(addr, n):
    buf = (ctypes.c_ubyte * n)()
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    return bytes(buf[:read.value]) if ok else b''

# 枚举可读 32-bit 地址空间
regions = []
addr = 0
mbi = MBI()
while addr < 0x80000000:
    ret = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not ret: break
    base = int(mbi.BaseAddress); size = int(mbi.RegionSize)
    if mbi.State == 0x1000 and (mbi.Protect & 0xff) in (0x02, 0x04, 0x20, 0x40, 0x80):
        if size < 64 * 1024 * 1024:
            regions.append((base, size, int(mbi.Type)))
    addr = base + size
print(f'regions: {len(regions)}')

# 目标字符串
TARGETS = [
    b'class wework::logic::PostSendMessageTask2\x00',
    b'class wework::logic::InitMessageSenderLookupTask\x00',
    b'class wework::logic::TimerUpdateMessageTimeTask\x00',   # 已知（对照组）
    b'class wework::logic::SetGlobalItemsTask\x00',           # 已知（对照组）
]

# Step 1: 找字符串所有地址
str_addrs = defaultdict(list)  # name -> [addr,...]
print('\n[Step 1] 扫描字符串地址...')
for base, size, _ in regions:
    data = rpm(base, min(size, 4*1024*1024))
    if not data: continue
    for needle in TARGETS:
        idx = 0
        while True:
            p = data.find(needle, idx)
            if p < 0: break
            name = needle.rstrip(b'\x00').decode('ascii', errors='replace')
            str_addrs[name].append(base + p)
            idx = p + 1
for name, addrs in str_addrs.items():
    print(f'  {name}: {len(addrs)} 处')
    for a in addrs[:5]:
        print(f'    0x{a:08x}')

# Step 2: 反向扫全内存找指向这些字符串的 4 字节指针
print('\n[Step 2] 反向扫指针（heap 优先）...')
# 优先扫 MEM_PRIVATE（heap）
priv_regions = [(b, s) for b, s, t in regions if t == 0x20000]  # MEM_PRIVATE
print(f'  MEM_PRIVATE regions: {len(priv_regions)}')

target_set = {}
for name, addrs in str_addrs.items():
    for a in addrs:
        target_set[a] = name

instances = defaultdict(list)  # name -> [(container_addr, str_field_offset_in_obj)]
scanned = 0
for base, size in priv_regions:
    data = rpm(base, min(size, 16*1024*1024))
    if not data: continue
    scanned += len(data)
    # 4 字节对齐扫描
    for i in range(0, len(data) - 4, 4):
        v = struct.unpack_from('<I', data, i)[0]
        if v in target_set:
            container_addr = base + i
            # 记录 (container, str_field_addr=v)
            instances[target_set[v]].append(container_addr)
    if scanned > 512 * 1024 * 1024:  # 512MB cap
        print(f'  扫描量到达上限 {scanned//1024//1024}MB，提前结束')
        break

print(f'\n[Step 3] 指针命中统计:')
for name, addrs in instances.items():
    print(f'  {name}: {len(addrs)} 处指针指向')
    for a in addrs[:10]:
        # 尝试把 a 作为"对象内嵌字符串字段"，回推对象起始（尝试常见 offset）
        # 对照第十二轮 §29.3：类名通常在 obj+96/+128/+192 等
        for guess_off in (0, 8, 16, 32, 64, 96, 128, 160, 192, 224):
            obj_start = a - guess_off
            obj = rpm(obj_start, 8)
            if len(obj) >= 4:
                vt = struct.unpack_from('<I', obj, 0)[0]
                # vtable 通常在 WXWork.exe 代码段 (0x2D0000 起 ~300MB)
                if 0x2D0000 <= vt < 0x2D0000 + 300*1024*1024:
                    print(f'    ptr@0x{a:08x}  obj_start=0x{obj_start:08x} (str_off_in_obj=+{guess_off})  vtable=0x{vt:08x}')
                    break
        else:
            print(f'    ptr@0x{a:08x}  (no valid vtable in 224B before)')

# Step 4: 详细 dump 每个 PostSendMessageTask2 实例（限 top 5）
print('\n[Step 4] PostSendMessageTask2 实例内容 dump:')
name_target = 'class wework::logic::PostSendMessageTask2'
seen_objs = set()
count = 0
for ptr_addr in instances.get(name_target, []):
    if count >= 5: break
    # 试各 offset 找 vtable
    for guess_off in (0, 8, 16, 32, 64, 96, 128, 160, 192, 224, 256):
        obj_start = ptr_addr - guess_off
        if obj_start in seen_objs: continue
        obj = rpm(obj_start, 320)
        if len(obj) < 4: continue
        vt = struct.unpack_from('<I', obj, 0)[0]
        if 0x2D0000 <= vt < 0x2D0000 + 300*1024*1024:
            seen_objs.add(obj_start)
            count += 1
            print(f'\n  === Instance @ 0x{obj_start:08x}  (str_off=+{guess_off}, vtable=0x{vt:08x}) ===')
            for j in range(0, min(len(obj), 320), 32):
                seg = obj[j:j+32]
                ascii_s = ''.join(chr(x) if 32<=x<127 else '.' for x in seg)
                print(f'    [+{j:03d}] {seg.hex()} | {ascii_s}')
            # dump vtable 前 8 项（32 字节）
            vt_data = rpm(vt, 32)
            if vt_data:
                fns = struct.unpack('<8I', vt_data)
                print(f'    vtable[0:8] = {[f"0x{f:08x}" for f in fns]}')
            break

# 保存
out = OUT / 'task_instances.json'
out.write_text(json.dumps({
    'pid': pid,
    'str_addrs': {k: [f'0x{a:08x}' for a in v] for k, v in str_addrs.items()},
    'instances_count': {k: len(v) for k, v in instances.items()},
    'instances_sample': {
        k: [f'0x{a:08x}' for a in v[:20]] for k, v in instances.items()
    },
    'scanned_MB': scanned // 1024 // 1024,
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] {out}')
k32.CloseHandle(h)
