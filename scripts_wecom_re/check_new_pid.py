"""
简化版扫描，逐区域捕获异常
"""
import sys, importlib.util, pathlib, ctypes, ctypes.wintypes, struct, time
from datetime import datetime, timezone

spec = importlib.util.spec_from_file_location(
    'wecom_memory_reader',
    pathlib.Path('app/pc_wecom/wecom_memory_reader.py')
)
mod = importlib.util.module_from_spec(spec)
sys.modules['wecom_memory_reader'] = mod
spec.loader.exec_module(mod)

find_wxwork_pid = mod.find_wxwork_pid
pid = find_wxwork_pid()
print(f'PID: {pid}')

# 直接用 ctypes（不经过 wecom_memory_reader 扫描器）
kernel32 = ctypes.windll.kernel32
hProc = kernel32.OpenProcess(0x0010 | 0x0400, False, pid)
print(f'hProc: {hProc}')

class MBI(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', ctypes.wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', ctypes.wintypes.DWORD),
        ('Protect', ctypes.wintypes.DWORD),
        ('Type', ctypes.wintypes.DWORD),
    ]

mbi = MBI()
cursor = 0x10000
region_count = 0
readable_mb = 0

while cursor < 0x7FFF0000:
    ret = kernel32.VirtualQueryEx(hProc, ctypes.c_void_p(cursor), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if ret == 0:
        break
    if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x20, 0x40, 0x44, 0x24, 0x80):
        region_count += 1
        readable_mb += mbi.RegionSize // (1024 * 1024)
    next_cursor = cursor + max(mbi.RegionSize, 0x1000)
    if next_cursor <= cursor:
        break
    cursor = next_cursor

print(f'可读区域: {region_count} 个，约 {readable_mb} MB')
kernel32.CloseHandle(hProc)
print('OK')
