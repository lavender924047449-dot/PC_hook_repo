# P2: Read the 10-entry type-name table at 0xcf55048~0xcf55098
# Each entry = {int type_code, char* type_name}
import pefile, sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PE_PATH = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
pe = pefile.PE(PE_PATH, fast_load=True)
IB = 0x400000

TABLE_START = 0xcf55048
TABLE_END   = 0xcf55098
N = (TABLE_END - TABLE_START) // 8

def read_va(va, n):
    """Read n bytes from VA, resolving section."""
    for s in pe.sections:
        vs, vsz = IB + s.VirtualAddress, s.Misc_VirtualSize
        if vs <= va < vs + vsz:
            off = va - vs
            data = s.get_data()
            end = min(off + n, len(data))
            return data[off:end]
    return None

def read_cstr(va, maxlen=256):
    d = read_va(va, maxlen)
    if d is None:
        return None
    z = d.find(b'\x00')
    if z < 0:
        z = len(d)
    try:
        return d[:z].decode('utf-8', errors='replace')
    except Exception:
        return d[:z].hex()

print(f'=== Type-name table @ 0x{TABLE_START:x} ~ 0x{TABLE_END:x}  ({N} entries) ===\n')
tbl = read_va(TABLE_START, N * 8)
if tbl is None:
    print('!! table VA not in any section — pe layout unusual')
    sys.exit(1)

print(f'{"#":>3}  {"type_code":>12}  {"name_ptr":>10}  {"type_name"}')
print('-' * 100)
for i in range(N):
    entry = tbl[i*8:(i+1)*8]
    type_code, name_ptr = struct.unpack('<II', entry)
    name = read_cstr(name_ptr) if name_ptr else '<null>'
    print(f'{i:>3}  0x{type_code:08x}({type_code:>6})  0x{name_ptr:08x}  {name!r}')

# P3: also read vtable 0xae85370 neighborhood in .rdata to identify the class
print('\n=== P3: vt 0xae85370 neighborhood (looking for class name string) ===')
VT = 0xae85370
# The class name for MSVC RTTI is typically at (vt - 4) → col ptr → typeDescriptor → name
# But easier heuristic (§47.16.10): the type-name string sits adjacent in .rdata to the vtable
# Try: read the dword at (vt - 4) which is the RTTI complete object locator
col_ptr = read_va(VT - 4, 4)
if col_ptr:
    col = struct.unpack('<I', col_ptr)[0]
    print(f'RTTI COL ptr = 0x{col:x}')
    # COL = { signature, offset, cdOffset, pTypeDescriptor, pClassHierarchy, ... }
    col_data = read_va(col, 20)
    if col_data:
        sig, off, cd, ptd, pch = struct.unpack('<IIIII', col_data)
        print(f'  sig=0x{sig:x} off={off} cd={cd} typeDesc=0x{ptd:x} classHier=0x{pch:x}')
        # TypeDescriptor = { vftable_ptr, spare, name_string ... }
        td_data = read_va(ptd, 128)
        if td_data:
            # skip first 8 bytes (vfptr + spare) → name starts at offset 8
            name_bytes = td_data[8:]
            z = name_bytes.find(b'\x00')
            if z > 0:
                print(f'  ★ class name = {name_bytes[:z].decode("utf-8", errors="replace")!r}')

# Also do §47.16.10-style neighborhood scan: search around VT-0x200..VT+0x200 for printable strings
print('\n=== Neighborhood ASCII scan around vt 0xae85370 (±0x200) ===')
neigh = read_va(VT - 0x200, 0x400)
if neigh:
    cur = b''
    for i, b in enumerate(neigh):
        if 32 <= b < 127:
            cur += bytes([b])
        else:
            if len(cur) >= 8 and (b'.' in cur or b'_' in cur or b'::' in cur):
                addr = VT - 0x200 + i - len(cur)
                print(f'  @0x{addr:x}: {cur.decode()!r}')
            cur = b''
