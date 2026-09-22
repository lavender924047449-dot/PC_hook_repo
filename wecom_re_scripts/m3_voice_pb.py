# voice message content protobuf — 字段顺序来自 trace_voice 内存样本
from __future__ import annotations

def _varint(n: int) -> bytes:
    n = int(n)
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)

def _bytes_field(fn: int, data: bytes) -> bytes:
    return _varint((fn << 3) | 2) + _varint(len(data)) + data

def _varint_field(fn: int, v: int) -> bytes:
    return _varint((fn << 3) | 0) + _varint(v)

def build_voice_content_pb(
    filename: str,
    file_id: str,
    md5: str,
    duration_ms: int = 5000,
) -> bytes:
    """trace 样本：f2=filename, f3=nested(duration…), f8=file_id, f10=md5。"""
    fn = filename.encode("ascii")
    fid = file_id.encode("ascii")
    md = md5.encode("ascii")
    nested = _varint_field(1, max(1, duration_ms // 1000))
    nested += _bytes_field(2, b"\x0a\x03" + b"123")  # trace 常见占位；UI 不展示
    body = _bytes_field(2, fn)
    body += _bytes_field(3, nested)
    body += _bytes_field(8, fid)
    body += _bytes_field(10, md)
    return body

def wrap_package_body_pb(inner: bytes) -> bytes:
    """package+0x1b8 处外层：0a [len] [inner]（与 PC voice dump 一致）。"""
    return _bytes_field(1, inner)

def load_voice_template_slices() -> dict[str, bytes]:
    import json
    from pathlib import Path
    p = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\pkg_layout_voice_20260913_181713.json")
    pkg = bytes.fromhex(json.loads(p.read_text(encoding="utf-8"))["tasks"][0]["pkg_hex"])
    return {
        "off54": pkg[0x54:0x58],
        "off100": pkg[0x100:0x108],
        "off120": pkg[0x120:0x130],
        "off163": pkg[0x163:0x164],
        "off1c8": pkg[0x1c8:0x1d0],
        "off1d0": pkg[0x1D0:0x1E0],
    }
