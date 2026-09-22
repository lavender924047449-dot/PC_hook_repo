# 从 trace 内存样本构造 voice message protobuf + 对比 package 模板
from __future__ import annotations
import json, re, struct
from pathlib import Path

def varint(n: int) -> bytes:
    out = bytearray()
    while n > 0x7f:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)

def field_bytes(fn: int, data: bytes) -> bytes:
    return varint((fn << 3) | 2) + varint(len(data)) + data

def field_varint(fn: int, v: int) -> bytes:
    return varint((fn << 3) | 0) + varint(v)

def build_voice_pb(filename: str, file_id: str, md5: str, duration_ms: int = 0) -> bytes:
    """按 trace_voice 内存 layout 构造外层 voice content protobuf。"""
    inner = field_varint(1, duration_ms)  # 0x08 duration
    inner += field_bytes(2, b"\x0a\x03" + b"123")  # placeholder nested — 真实 voice 更复杂
    body = field_bytes(2, filename.encode("ascii"))
    body += field_bytes(3, inner)
    body += field_bytes(8, file_id.encode("ascii"))
    body += field_bytes(10, md5.encode("ascii"))
    return body

def extract_from_trace():
    p = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\trace_voice_20260913_185747.json")
    data = json.loads(p.read_text(encoding="utf-8"))
    for ev in data.get("memory_events", []):
        ctx = ev.get("ctx", "")
        if "388dc3ce7ba84680bc5ead8330e961c8" in ctx and ".silk" in ctx:
            # 找 0x12 0x1c filename 后的 raw bytes
            idx = ctx.find("\x12\x1c")
            if idx >= 0:
                raw = ctx[idx:idx+120].encode("latin-1", errors="replace") if isinstance(ctx, str) else ctx[idx:idx+120]
                print("trace slice hex:", raw[:80].hex() if isinstance(raw, bytes) else repr(raw[:80]))
            return ctx
    return None

def main():
    staged = json.loads(Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\poc_staged_voice.json").read_text())
    pb = build_voice_pb(staged["filename"], "388dc3ce7ba84680bc5ead8330e961c8", staged["md5"])
    print("built pb len", len(pb), pb.hex())

    OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
    voice = bytes.fromhex(json.loads((OUT/"pkg_layout_voice_20260913_181713.json").read_text())["tasks"][0]["pkg_hex"])
    # voice inline pb at +0x1b8
    inline = voice[0x1b8:0x1b8+29]
    print("voice inline @+0x1b8:", inline.hex())

    extract_from_trace()

if __name__ == "__main__":
    main()
