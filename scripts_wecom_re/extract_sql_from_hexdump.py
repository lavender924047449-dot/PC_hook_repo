from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


KEY_RE = re.compile(r"(?i)\b(select|insert|update|delete|create|pragma|from|where|join)\b")
ASCII_RE = re.compile(r"[ -~]{6,}")


def decode_hexdump(h: str) -> bytes:
    hex_pairs = re.findall(r"\b[0-9a-fA-F]{2}\b", h or "")
    return bytes.fromhex("".join(hex_pairs)) if hex_pairs else b""


def extract_ascii(b: bytes) -> list[str]:
    if not b:
        return []
    text = b.decode("latin-1", errors="ignore")
    return ASCII_RE.findall(text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract SQL-like ASCII fragments from hexdump fields.")
    parser.add_argument("--infile", required=True)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    p = Path(args.infile)
    data = json.loads(p.read_text(encoding="utf-8"))
    events = data.get("events", [])
    findings = []

    for e in events:
        frags = []
        for key in ("h0", "h1", "h2"):
            b = decode_hexdump(str(e.get(key, "")))
            for frag in extract_ascii(b):
                if KEY_RE.search(frag):
                    frags.append({"src": key, "text": frag})
        if frags:
            findings.append(
                {
                    "ts": e.get("ts"),
                    "ret": e.get("ret"),
                    "s0": e.get("s0", ""),
                    "fragments": frags[:10],
                    "bt_head": (e.get("bt") or [])[:8],
                }
            )

    out = {"infile": str(p), "event_count": len(events), "sql_like_event_count": len(findings), "findings": findings}
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.out:
        op = Path(args.out)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
