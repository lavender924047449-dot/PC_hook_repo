# 从 trace_voice JSON 提取 voice content protobuf 原始字节
import json, re
from pathlib import Path

def main():
    p = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\trace_voice_20260913_185747.json")
    data = json.loads(p.read_text(encoding="utf-8"))
    best = None
    for ev in data.get("memory_events", []):
        ctx = ev.get("ctx", "")
        if "388dc3ce7ba84680bc5ead8330e961c8" not in ctx:
            continue
        if "2026_09_13_18_56_51_226.silk" not in ctx:
            continue
        # 找 \x12\x1c 起始
        for marker in ["\x12\x1c", "\u0012\u001c"]:
            i = ctx.find(marker)
            if i < 0:
                continue
            raw = ctx[i:].encode("latin-1", errors="surrogateescape") if isinstance(ctx, str) else ctx[i:]
            if best is None or len(raw) > len(best):
                best = raw[:200]
    if not best:
        print("not found"); return
    print("len", len(best))
    print("hex", best.hex())
    # 找 file_id / md5 位置
    for label, pat in [("file_id", b"388dc3ce7ba84680bc5ead8330e961c8"), ("md5", b"a74bb27cc1058dde266cefb725ae9aad")]:
        j = best.find(pat)
        print(label, "at", j)

if __name__ == "__main__":
    main()
