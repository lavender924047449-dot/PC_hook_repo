# P4 + P5: 全库扫 ww_richmessage.* 类名 + 定位 ww_richmessage.Message 的 vt/RTTI
# 目的：确认是否存在 VoiceMessage / VoiceContent 之类 concrete 类；
#      如果没有，voice 只可能作为 Message 的 content_type 存在 → 找 Message vt 是关键
import pefile, sys, struct, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PE_PATH = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
pe = pefile.PE(PE_PATH, fast_load=True)
IB = 0x400000

# ---- 1. 全库扫 ww_richmessage.* / ww_msg.* / *_message.pb.cc ----
PAT_CLASS = re.compile(rb'ww_richmessage\.[A-Za-z_][A-Za-z0-9_]{2,60}')
PAT_PB    = re.compile(rb'[A-Za-z0-9_\\/:.-]{4,120}\.pb\.cc')
PAT_MSGCLS = re.compile(rb'\.\?AV[A-Za-z_][A-Za-z0-9_]{2,80}@ww_richmessage@@')
PAT_CONT = re.compile(rb'CONTENT_[A-Z_]+')

classes = set()
pbfiles = set()
rtti_classes = set()
contents = set()

for s in pe.sections:
    d = s.get_data()
    sec_va = IB + s.VirtualAddress
    for m in PAT_CLASS.finditer(d):
        va = sec_va + m.start()
        classes.add((m.group().decode('ascii'), va))
    for m in PAT_PB.finditer(d):
        try:
            pbfiles.add(m.group().decode('ascii'))
        except Exception:
            pass
    for m in PAT_MSGCLS.finditer(d):
        va = sec_va + m.start()
        rtti_classes.add((m.group().decode('ascii'), va))
    for m in PAT_CONT.finditer(d):
        contents.add(m.group().decode('ascii'))

print(f'=== ww_richmessage.* 类名字符串（去重 {len(classes)}） ===')
for name, va in sorted(classes):
    print(f'  0x{va:08x}  {name}')

print(f'\n=== .?AV*@ww_richmessage@@ RTTI 类名（去重 {len(rtti_classes)}） ===')
for name, va in sorted(rtti_classes):
    print(f'  0x{va:08x}  {name}')

print(f'\n=== CONTENT_* 枚举字符串（去重 {len(contents)}） ===')
for c in sorted(contents):
    print(f'  {c}')

print(f'\n=== *_message.pb.cc（去重 {len(pbfiles)}） ===')
for f in sorted(pbfiles):
    print(f'  {f}')

# ---- 2. 找 ww_richmessage.Message 的 vt: 用 .rdata 里 RTTI 反查 ----
# 逻辑：找 '.?AVMessage@ww_richmessage@@' TypeDescriptor VA
#      然后在 pe 里找 CompleteObjectLocator（含该 TD ptr）
#      然后从 COL VA 反查 vtable（vtable[-1] = COL ptr）
target_rtti_name = b'.?AVMessage@ww_richmessage@@'

def find_bytes_va(needle, aligned=False):
    """Return list of VA where needle appears."""
    hits = []
    for s in pe.sections:
        d = s.get_data()
        base = IB + s.VirtualAddress
        off = 0
        while True:
            i = d.find(needle, off)
            if i < 0: break
            hits.append(base + i)
            off = i + 1
    return hits

def read_va(va, n):
    for s in pe.sections:
        vs, vsz = IB + s.VirtualAddress, s.Misc_VirtualSize
        if vs <= va < vs + vsz:
            off = va - vs
            data = s.get_data()
            return data[off:min(off+n, len(data))]
    return None

def find_u32_va(u32_le, aligned=False):
    """Find VA of 4-byte little-endian occurrences of u32."""
    needle = struct.pack('<I', u32_le)
    hits = []
    for s in pe.sections:
        d = s.get_data()
        base = IB + s.VirtualAddress
        off = 0
        while True:
            i = d.find(needle, off)
            if i < 0: break
            if not aligned or i % 4 == 0:
                hits.append(base + i)
            off = i + 1
    return hits

print(f'\n=== 定位 {target_rtti_name.decode()} ===')
name_hits = find_bytes_va(target_rtti_name)
print(f'RTTI name string VAs: {[hex(v) for v in name_hits]}')
for name_va in name_hits:
    # TypeDescriptor 格式: [vfptr:4][spare:4][name...] ; name 从 offset +8 起
    # 所以 TD VA = name_va - 8
    td_va = name_va - 8
    print(f'  疑似 TD @ 0x{td_va:x}')
    # 找哪些 COL 指向这个 TD（COL[3] = pTypeDescriptor）
    col_refs = find_u32_va(td_va, aligned=True)
    print(f'  找到 {len(col_refs)} 处 4B 引用')
    for ref_va in col_refs:
        # COL 结构: [sig][off][cd][pTypeDescriptor][pClassHier]
        # ref_va 应该指向 COL+0xc（pTypeDescriptor 字段）
        col_start = ref_va - 0xc
        col_data = read_va(col_start, 20)
        if col_data and len(col_data) >= 20:
            sig, off, cd, ptd, pch = struct.unpack('<IIIII', col_data)
            if ptd == td_va and sig in (0, 1):
                # 找哪些 vtable[-1] 指向此 COL
                vt_refs = find_u32_va(col_start, aligned=True)
                for vt_ref in vt_refs:
                    vt_va = vt_ref + 4    # vt_ref 是 vtable[-1] 的位置，vt 本身在 +4
                    # 读前 8 个 slot
                    slots = read_va(vt_va, 32)
                    if slots and len(slots) == 32:
                        vt = struct.unpack('<8I', slots)
                        print(f'    ★ vtable @ 0x{vt_va:x}: {[hex(v) for v in vt]}')
                        # 邻近扫，看隔壁是不是别的 ww_richmessage.* 类名
                        neigh = read_va(vt_va - 0x40, 0x100)
                        if neigh:
                            cur = b''
                            for i, bt in enumerate(neigh):
                                if 32 <= bt < 127:
                                    cur += bytes([bt])
                                else:
                                    if len(cur) >= 8 and (b'.' in cur or b'_' in cur):
                                        addr = vt_va - 0x40 + i - len(cur)
                                        if b'ww_' in cur or b'.pb.' in cur or b'CONTENT_' in cur:
                                            print(f'      near @0x{addr:x}: {cur.decode()!r}')
                                    cur = b''
