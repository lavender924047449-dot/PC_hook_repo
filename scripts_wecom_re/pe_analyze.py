"""
pe_analyze.py - 离线 PE 分析，找 ForwardMessageToWeChatInternal 代码引用
"""
import pefile, struct, sys

pe_path = r'D:\Cursor_env\企业微信\WXWork\WXWork.exe'
TARGET = b"ForwardMessageToWeChatInternal"

print("Loading PE...")
pe = pefile.PE(pe_path, fast_load=True)
img_base = pe.OPTIONAL_HEADER.ImageBase
print(f"ImageBase: 0x{img_base:08X}")
print(f"Sections:")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    print(f"  {name:<12} VA=0x{s.VirtualAddress:08X} VSize=0x{s.Misc_VirtualSize:08X} "
          f"RawOff=0x{s.PointerToRawData:08X} RawSize=0x{s.SizeOfRawData:08X}")

# 读取整个文件
print("\nReading file...")
with open(pe_path, 'rb') as f:
    raw = f.read()
print(f"File size: {len(raw):,} bytes")

# Step 1: 找字符串的文件偏移
str_offsets = []
pos = 0
while True:
    idx = raw.find(TARGET, pos)
    if idx < 0: break
    str_offsets.append(idx)
    pos = idx + 1

print(f"\nFound {len(str_offsets)} occurrences of '{TARGET.decode()}' in file")
for off in str_offsets[:4]:
    # 转换为 RVA
    try:
        rva = pe.get_rva_from_offset(off)
        # 找所在 section
        section_name = "?"
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                section_name = s.Name.rstrip(b'\x00').decode('latin1')
                break
        print(f"  file@0x{off:08X}  RVA=0x{rva:08X}  section={section_name}  "
              f"ctx={raw[off:off+40].decode('latin1', errors='replace')!r}")
    except Exception as e:
        print(f"  file@0x{off:08X}  RVA error: {e}")

if not str_offsets:
    print("ERROR: 字符串未在文件中找到（可能是压缩/加密节）")
    sys.exit(1)

# Step 2: 对每个字符串位置，搜索代码引用
# 搜索方式 A: push OFFSET (E8 xx xx xx xx 之前的 push 68 xx xx xx xx)
# 搜索方式 B: 直接搜索 4-byte LE(img_base + RVA) in code sections

print("\nSearching for code references (PUSH OFFSET pattern)...")
code_refs = []
for off in str_offsets[:4]:
    try:
        rva = pe.get_rva_from_offset(off)
        abs_addr = img_base + rva  # 默认加载地址下的绝对地址
        # 4-byte LE
        pattern = struct.pack('<I', abs_addr)
        # 在代码节中搜索
        for s in pe.sections:
            if not (s.Characteristics & 0x20000000):  # CODE flag
                continue
            sec_data = raw[s.PointerToRawData : s.PointerToRawData + s.SizeOfRawData]
            search_pos = 0
            while True:
                idx2 = sec_data.find(pattern, search_pos)
                if idx2 < 0: break
                # 检查前1字节是否是 push (0x68) 或 mov (0xBx, 0xC7 etc)
                instr_byte = sec_data[idx2-1] if idx2 > 0 else 0
                file_code_off = s.PointerToRawData + idx2
                code_rva = s.VirtualAddress + idx2
                code_refs.append({
                    'str_rva': rva,
                    'ref_file_off': file_code_off,
                    'ref_rva': code_rva,
                    'instr_byte': instr_byte,
                    'context': sec_data[max(0,idx2-5):idx2+10].hex()
                })
                search_pos = idx2 + 1
    except Exception as e:
        print(f"  error: {e}")

print(f"Found {len(code_refs)} code references:")
for r in code_refs[:20]:
    print(f"  str_RVA=0x{r['str_rva']:08X} <- code_RVA=0x{r['ref_rva']:08X} "
          f"prev_byte=0x{r['instr_byte']:02X} ctx={r['context']}")

# Step 3: 若没找到，搜索 RVA 格式 (相对引用)
if not code_refs:
    print("\nNo absolute refs. Trying RVA-format references...")
    for off in str_offsets[:4]:
        try:
            rva = pe.get_rva_from_offset(off)
            # 搜索 RVA 作为 4-byte LE
            pattern = struct.pack('<I', rva)
            pos2 = 0
            while True:
                idx3 = raw.find(pattern, pos2)
                if idx3 < 0: break
                try:
                    ref_rva2 = pe.get_rva_from_offset(idx3)
                    sec = "?"
                    for s in pe.sections:
                        if s.VirtualAddress <= ref_rva2 < s.VirtualAddress + s.Misc_VirtualSize:
                            sec = s.Name.rstrip(b'\x00').decode('latin1')
                    print(f"  str_RVA=0x{rva:08X} <-rva- file@0x{idx3:08X} "
                          f"(RVA=0x{ref_rva2:08X} sec={sec})")
                except:
                    pass
                pos2 = idx3 + 1
        except Exception as e:
            print(f"  {e}")
