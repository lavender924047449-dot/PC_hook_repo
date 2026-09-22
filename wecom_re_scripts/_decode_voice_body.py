"""
对比:
  A) 真实语音 task 的 +0x1b8 std::string body (pkg_layout_voice_181713)
  B) 我们注入的 voice proto (m3_hijack_224333)
  C) 真实文件 task 的 +0x1b8 body (pkg_layout_file_183259)
并尝试用 protobuf 手工解析
"""
import json, struct
from pathlib import Path

OUT = Path(__file__).resolve().parent

def read_std_string_bytes(pkg: bytes, off: int) -> bytes:
    """MSVC 32-bit std::string layout"""
    if off + 0x18 > len(pkg):
        return b""
    heap_ptr  = struct.unpack_from("<I", pkg, off)[0]
    size      = struct.unpack_from("<I", pkg, off + 0x10)[0]
    cap       = struct.unpack_from("<I", pkg, off + 0x14)[0]
    if size == 0 or size > 0x10000:
        return b""
    if size <= 15 or cap == 15:          # SSO: data stored inline
        return bytes(pkg[off: off + size])
    # Heap: data at heap_ptr — we only have the dump, not the heap
    return b""   # can't read heap from dump

def varint_decode(data: bytes, pos: int):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos

def pb_parse(data: bytes):
    """minimal protobuf field printer"""
    pos = 0; fields = []
    while pos < len(data):
        tag_varint, pos = varint_decode(data, pos)
        field_num = tag_varint >> 3
        wire_type = tag_varint & 7
        if wire_type == 0:
            val, pos = varint_decode(data, pos)
            fields.append((field_num, "varint", val))
        elif wire_type == 2:
            length, pos = varint_decode(data, pos)
            val = data[pos:pos+length]; pos += length
            try:
                s = val.decode("utf-8")
            except Exception:
                s = val.hex()
            fields.append((field_num, "bytes", s if isinstance(s, str) else val.hex()))
        elif wire_type == 5:
            val = struct.unpack_from("<I", data, pos)[0]; pos += 4
            fields.append((field_num, "fixed32", f"0x{val:08x}"))
        elif wire_type == 1:
            val = struct.unpack_from("<Q", data, pos)[0]; pos += 8
            fields.append((field_num, "fixed64", f"0x{val:016x}"))
        else:
            print(f"  [!] unknown wire type {wire_type} at pos {pos-1}, stop")
            break
    return fields

def decode_pkg(path: str, label: str, off_1b8: int = 0x1b8):
    data = json.loads(Path(path).read_text())
    tasks = data.get("tasks") or data.get("events") or []
    if not tasks: return
    t = tasks[0]
    raw = bytes.fromhex(t.get("pkg_hex",""))
    print(f"\n{'='*60}")
    print(f"[{label}]  pkg_hex len={len(raw)}")
    # subtype
    if len(raw) > 0x54:
        print(f"  +0x50 subtype : {raw[0x50]:02x} (dword={raw[0x50:0x54].hex()})")
        print(f"  +0x54..0x58   : {raw[0x54:0x58].hex()} (voice='20 43 65 72')")
    # std::string at +0x1b8
    if len(raw) >= off_1b8 + 0x18:
        hp  = struct.unpack_from("<I", raw, off_1b8)[0]
        sz  = struct.unpack_from("<I", raw, off_1b8 + 0x10)[0]
        cap = struct.unpack_from("<I", raw, off_1b8 + 0x14)[0]
        print(f"  +0x1b8 std::string  ptr=0x{hp:08x}  size={sz}  cap={cap}")
        body = read_std_string_bytes(raw, off_1b8)
        if body:
            print(f"  body ({len(body)}B): {body.hex()}")
            print(f"  protobuf fields:")
            for f in pb_parse(body):
                print(f"    field {f[0]} [{f[1]}] = {f[2]}")
        else:
            print(f"  body: (heap-allocated, cannot read from dump)")

# 真实语音 task
decode_pkg(str(OUT/"pkg_layout_voice_20260913_181713.json"), "REAL VOICE task (captured)")

# 注入后的 patched task
decode_pkg(str(OUT/"m3_hijack_20260913_224333.json"), "PATCHED task (m3 hijack 22:43)")

# 真实文件 task
decode_pkg(str(OUT/"pkg_layout_file_20260913_183259.json"), "REAL FILE task (captured)")

# 也打印真实语音包的 +0x54 字段
print("\n=== ADDITIONAL: pkg_layout_voice +0x1af..+0x1d0 ===")
data = json.loads((OUT/"pkg_layout_voice_20260913_181713.json").read_text())
raw = bytes.fromhex(data["tasks"][0]["pkg_hex"])
if len(raw) >= 0x1d0:
    for off in range(0x1a0, min(0x1d4, len(raw)), 4):
        print(f"  +0x{off:03x}: {raw[off:off+4].hex()}")
