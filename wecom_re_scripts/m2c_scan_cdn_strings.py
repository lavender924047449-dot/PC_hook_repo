# m2c_scan_cdn_strings.py — 磁盘扫 WXWork.exe 里 CdnUploadParam / FileService 线索
# 只读文件，不 attach。

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

EXE = Path(r"D:\Cursor_env\企业微信\WXWork\WXWork.exe")
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\m2c_cdn_strings.json")

NEEDLES = [
    b"CdnUploadParam",
    b"CdnUploadFile",
    b"CdnDownloadParam",
    b"upload_cdn_file_task2.cpp",
    b"FileService::CdnUploadFile",
    b"file_path",
    b"file_type",
    b"aes_key",
    b"fileid",
    b"file_id",
    b"voice_time",
    b"play_time",
    b"conversation_id",
    b"conv_id",
    b"local_path",
    b"CdnFileType",
    b"CDN_FILE_TYPE",
    b"kCdnFileType",
    b"CdnUploadResult",
]


def ascii_around(buf: bytes, pos: int, radius: int = 96) -> str:
    lo = max(0, pos - radius)
    hi = min(len(buf), pos + radius)
    chunk = buf[lo:hi]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def main() -> int:
    if not EXE.is_file():
        print(f"[!] exe not found: {EXE}")
        return 1
    print(f"[*] reading {EXE} ({EXE.stat().st_size} bytes)...")
    data = EXE.read_bytes()
    hits: dict[str, list[dict]] = {}
    for needle in NEEDLES:
        key = needle.decode("ascii", errors="replace")
        recs = []
        start = 0
        while True:
            i = data.find(needle, start)
            if i < 0:
                break
            recs.append({"off": hex(i), "ctx": ascii_around(data, i)})
            start = i + 1
            if len(recs) >= 12:
                break
        hits[key] = recs
        print(f"  {key:28s}  {len(recs)} hit(s)")

    # proto-ish field names near first CdnUploadParam
    extra_fields: list[str] = []
    first = data.find(b"CdnUploadParam")
    if first >= 0:
        window = data[max(0, first - 0x400) : first + 0x800]
        extra_fields = sorted(
            set(
                m.group(0).decode("ascii")
                for m in re.finditer(rb"[a-z_][a-z0-9_]{2,32}", window)
            )
        )
        print(f"[+] field-like tokens near first CdnUploadParam ({len(extra_fields)}):")
        for t in extra_fields[:80]:
            print(f"    {t}")

    OUT.write_text(
        json.dumps({"hits": hits, "nearby_tokens": extra_fields}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[+] → {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
