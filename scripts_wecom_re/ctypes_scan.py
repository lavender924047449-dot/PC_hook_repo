"""
用 Python ctypes + ReadProcessMemory 扫描进程内存
比 Frida JS 快 10 倍，可扫更大范围
"""
import ctypes, ctypes.wintypes, struct, sys, json, pathlib
from datetime import datetime

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\ctypes_scan.json')

# Windows API setup
kernel32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]

# Open process
hProc = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, PID)
if not hProc:
    print(f"Failed to open process {PID}: {ctypes.GetLastError()}")
    sys.exit(1)

print(f"Opened process {PID}")

MIN_ST_HI = 0x18C   # 2024-01-01
MAX_ST_HI = 0x1A5   # 2026 end
MIN_SEQ = 1
MAX_SEQ = 10_000_000
MIN_TS_S = 1577836800  # 2020-01-01
MAX_TS_S = 1893456000  # 2030-01-01

results = []
CHUNK = 4 * 1024 * 1024  # 4MB read at once

# Enumerate readable memory regions
buf = ctypes.create_string_buffer(CHUNK)
mbi = MEMORY_BASIC_INFORMATION()
addr = 0x10000
total_scanned = 0
total_hits = 0

# Enumerate all readable writable regions
regions = []
addr_cursor = 0x10000
while addr_cursor < 0x7FFF0000:
    ret = kernel32.VirtualQueryEx(hProc, ctypes.c_void_p(addr_cursor), 
                                   ctypes.byref(mbi), ctypes.sizeof(mbi))
    if ret == 0:
        break
    protect = mbi.Protect
    state = mbi.State
    # State=0x1000 (MEM_COMMIT), Protect=rw variants (0x04, 0x20, 0x40, 0x80)
    if (state == 0x1000 and 
        protect in (0x04, 0x20, 0x40, 0x44, 0x24, 0x80) and  # PAGE_READWRITE variants
        mbi.RegionSize > 0 and 
        mbi.RegionSize <= 64*1024*1024):  # max 64MB per region
        regions.append((addr_cursor, mbi.RegionSize))
    
    next_addr = addr_cursor + max(mbi.RegionSize, 0x1000)
    if next_addr <= addr_cursor:
        break
    addr_cursor = next_addr

print(f"Found {len(regions)} readable regions, total {sum(s for _,s in regions)//1024//1024}MB")

# Scan each region
for (reg_base, reg_size) in regions:
    chunk_start = reg_base
    while chunk_start < reg_base + reg_size and len(results) < 1000:
        chunk_size = min(CHUNK, reg_base + reg_size - chunk_start)
        n_read = ctypes.c_size_t(0)
        data = ctypes.create_string_buffer(chunk_size)
        ok = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(chunk_start), data, chunk_size, ctypes.byref(n_read))
        if not ok or n_read.value < 16:
            chunk_start += chunk_size
            continue
        
        raw = data.raw[:n_read.value]
        total_scanned += len(raw)
        
        # Scan for (seq_lo, seq_hi=0, st_lo, st_hi) pattern
        # stride by 4 bytes
        for i in range(0, len(raw) - 16, 4):
            seq_lo, seq_hi, st_lo, st_hi = struct.unpack_from('<IIII', raw, i)
            if seq_hi != 0:
                continue
            if seq_lo < MIN_SEQ or seq_lo > MAX_SEQ:
                continue
            if st_hi < MIN_ST_HI or st_hi > MAX_ST_HI:
                continue
            st_ms = (st_hi << 32) | st_lo
            st_s = st_ms // 1000
            if st_s < MIN_TS_S or st_s > MAX_TS_S:
                continue
            addr = chunk_start + i
            results.append({
                'addr': hex(addr),
                'seq': seq_lo,
                'st_s': st_s,
                'st_ms': st_ms,
                'region': hex(reg_base)
            })
        
        chunk_start += chunk_size
    
    # Progress
    if total_scanned % (50*1024*1024) < CHUNK:
        print(f"  Scanned {total_scanned//1024//1024}MB, hits so far: {len(results)}")
        sys.stdout.flush()

kernel32.CloseHandle(hProc)

print(f"\nScan complete! {total_scanned//1024//1024}MB scanned, {len(results)} candidates")
for r in results[:30]:
    dt = datetime.utcfromtimestamp(r['st_s'])
    print(f"  addr={r['addr']} seq={r['seq']} ts={r['st_s']} ({dt.strftime('%Y-%m-%d %H:%M')} UTC) region={r['region']}")

OUT.write_text(json.dumps({
    'total_mb': total_scanned // 1024 // 1024,
    'count': len(results),
    'results': results[:200]
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'Saved {len(results)} results to {OUT}')
