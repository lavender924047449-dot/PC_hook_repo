# 对比 voice vs file package body（+0x180 起），解码 protobuf 片段
from __future__ import annotations
import json, re, struct, sys
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

def load_hex(path: Path) -> bytes:
    data = json.loads(path.read_text(encoding="utf-8"))
    tasks = data.get("tasks") or []
    if not tasks: raise ValueError(f"no tasks in {path.name}")
    hx = tasks[0].get("pkg_hex") or ""
    return bytes.fromhex(hx)

def hexdump(b: bytes, base=0) -> str:
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hx = " ".join(f"{x:02x}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"{base+i:04x}  {hx:<48}  {asc}")
    return "\n".join(lines)

def find_protobuf_regions(b: bytes) -> list[tuple[int, bytes]]:
    """找看起来像 protobuf 的连续区域（tag 0x08/0x0a/0x10/0x12/0x1a/0x42/0x52）"""
    hits = []
    for i in range(len(b)-4):
        if b[i] in (0x08, 0x0a, 0x10, 0x12, 0x1a, 0x42, 0x52, 0x62):
            # 向后取最多 128B
            seg = b[i:min(len(b), i+128)]
            if sum(1 for x in seg if x == 0) > len(seg)//2: continue
            hits.append((i, seg))
    return hits[:8]

def decode_varint(data, pos):
    val = shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80): return val, pos
        shift += 7
    return None, pos

def walk_pb(data, indent=0, max_depth=4):
    pos = 0
    out = []
    while pos < len(data) and max_depth > 0:
        start = pos
        tag, pos = decode_varint(data, pos)
        if tag is None: break
        fn, wt = tag >> 3, tag & 7
        if fn == 0 or fn > 100: break
        if wt == 0:
            v, pos = decode_varint(data, pos)
            out.append(f"{'  '*indent}f{fn} varint = {v}")
        elif wt == 2:
            ln, pos = decode_varint(data, pos)
            if ln is None or pos+ln > len(data): break
            payload = data[pos:pos+ln]; pos += ln
            asc = payload.decode('utf-8', errors='replace') if all(32<=c<127 or c in (10,13) for c in payload) and len(payload)<80 else None
            if asc:
                out.append(f"{'  '*indent}f{fn} str({ln}) = {asc!r}")
            else:
                out.append(f"{'  '*indent}f{fn} bytes({ln}) = {payload.hex()}")
                if ln > 2 and max_depth > 1:
                    sub = walk_pb(payload, indent+1, max_depth-1)
                    out.extend(sub)
        elif wt == 1:
            if pos+8 > len(data): break
            out.append(f"{'  '*indent}f{fn} fixed64 = {data[pos:pos+8].hex()}"); pos += 8
        elif wt == 5:
            if pos+4 > len(data): break
            out.append(f"{'  '*indent}f{fn} fixed32 = {data[pos:pos+4].hex()}"); pos += 4
        else:
            break
        if pos <= start: break
    return out

def main():
    voice = load_hex(OUT / "pkg_layout_voice_20260913_181713.json")
    file_ = load_hex(OUT / "pkg_layout_file_20260913_183259.json")
    hijack = None
    hj_path = OUT / "m3_hijack_20260913_210335.json"
    if hj_path.is_file():
        hj = json.loads(hj_path.read_text(encoding="utf-8"))
        hx = hj["result"]["patches"][0]["pkg_hex"]
        hijack = bytes.fromhex(hx)

    start, end = 0x180, 0x280
    v = voice[start:end]; f = file_[start:end]
    h = hijack[start:end] if hijack else None

    print("="*70)
    print("VOICE package +0x180..0x280")
    print(hexdump(v, start))
    print("\nFILE package +0x180..0x280")
    print(hexdump(f, start))
    if h:
        print("\nHIJACK(8→2) +0x180..0x280")
        print(hexdump(h, start))

    print("\n" + "="*70)
    print("BYTE DIFF voice vs file (only differing offsets)")
    for i in range(min(len(v), len(f))):
        if v[i] != f[i]:
            print(f"  +0x{start+i:03x}: voice={v[i]:02x} file={f[i]:02x}")

    # voice protobuf 可能在 inline 或 heap ptr — 从 voice 全包搜 0a 09 08
    idx = voice.find(bytes.fromhex("0a090800"))
    if idx >= 0:
        pb = voice[idx:idx+64]
        print(f"\n[VOICE protobuf @+0x{idx:x}]")
        print(walk_pb(pb))
        print(hexdump(pb, idx))

    # file: 找 filename heap string header at 0x1b8
    print(f"\n[FILE std::string @+0x1b8]")
    off = 0x1b8
    ptr = struct.unpack_from("<I", file_, off)[0]
    size = struct.unpack_from("<I", file_, off+0x10)[0]
    cap = struct.unpack_from("<I", file_, off+0x14)[0]
    print(f"  ptr=0x{ptr:x} size={size} cap={cap}")
    if size and size < 300:
        if size <= 15:
            raw = file_[off:off+size]
        else:
            print("  (heap ptr, need runtime read)")

    # voice std::string-like at 0x1d0 (file_id area?)
    print(f"\n[VOICE @+0x1d0 string-like]")
    for label, buf in [("voice", voice), ("file", file_)]:
        off = 0x1d0
        size = struct.unpack_from("<I", buf, off+0x10)[0] if off+0x14 <= len(buf) else 0
        cap = struct.unpack_from("<I", buf, off+0x14)[0] if off+0x18 <= len(buf) else 0
        print(f"  {label}: size={size} cap={cap}")

if __name__ == "__main__":
    main()
