from __future__ import annotations

import argparse
import json
from pathlib import Path

import frida


JS = r"""
const KEY = "SQLite format 3";
const hits = [];
const ranges = Process.enumerateRanges("r--");
let scanned = 0;
for (let i = 0; i < ranges.length; i++) {
  const r = ranges[i];
  if (r.size < 0x1000 || r.size > 0x4000000) continue;
  scanned += r.size;
  let found;
  try { found = Memory.scanSync(r.base, r.size, KEY); }
  catch (e) { continue; }
  for (let j = 0; j < found.length && hits.length < 24; j++) {
    const p = found[j].address;
    let pageSize = 0;
    try { pageSize = (p.add(16).readU8() << 8) | p.add(17).readU8(); } catch (e) {}
    if (pageSize === 1) pageSize = 65536;
    let header = "";
    let master = "";
    try { header = hexdump(p, { offset: 0, length: 64, header: false, ansi: false }); } catch (e) {}
    try { master = p.readCString() ? "" : ""; } catch (e) {}
    let window = "";
    try {
      const n = Math.min(r.base.add(r.size).sub(p).toInt32(), 4096);
      window = p.readUtf8String ? "" : "";
      const bytes = new Uint8Array(p.readByteArray(Math.min(2048, n)));
      let s = "";
      for (let k = 0; k < bytes.length; k++) {
        const c = bytes[k];
        s += (c >= 32 && c < 127) ? String.fromCharCode(c) : " ";
      }
      window = s;
    } catch (e) {}
    const interesting = window.indexOf("message_table") >= 0 || window.indexOf("sqlite_master") >= 0 || window.indexOf("message_lookup") >= 0;
    hits.push({
      va: p.toString(),
      page_size: pageSize,
      interesting: interesting,
      snippet: window.replace(/\s+/g, " ").slice(0, 400)
    });
  }
  if (hits.length >= 24) break;
}
send({ range_count: ranges.length, scanned_hint: scanned, hit_count: hits.length, hits: hits });
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan process memory for SQLite headers / message_table text.")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--out", default="runtime/wecom_re/sqlite_mem_scan.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []
    sess = frida.attach(args.pid)
    try:
        script = sess.create_script(JS)

        def on_message(msg, data):
            if msg.get("type") == "send":
                events.append(msg.get("payload", {}))
            elif msg.get("type") == "error":
                events.append({"error": msg})

        script.on("message", on_message)
        script.load()
        script.unload()
    finally:
        sess.detach()

    payload = events[0] if events else {"error": "no payload", "raw": events}
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    interesting = [h for h in payload.get("hits", []) if h.get("interesting")]
    print(
        json.dumps(
            {
                "out": str(out),
                "hit_count": payload.get("hit_count"),
                "interesting": len(interesting),
                "interesting_va": [h.get("va") for h in interesting[:12]],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
