from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Trace message_lookup query events from logger hook and dump raw buffers."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0", help="Logger function runtime address.")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--hexdump-len", type=int, default=256)
    parser.add_argument(
        "--query-keyword",
        default="select sequence, send_time from message_table where message_id = ? limit 1;",
    )
    parser.add_argument("--out", default="runtime/wecom_re/message_lookup_query_trace.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = f"""
const target = ptr("{args.addr}");
const HEX_LEN = {max(32, int(args.hexdump_len))};
const KEY = "{args.query_keyword}".toLowerCase();

function s8(p) {{ try {{ return p.readCString(); }} catch (e) {{ return ""; }} }}
function h(p) {{
  try {{
    return hexdump(p, {{ offset: 0, length: HEX_LEN, header: false, ansi: false }});
  }} catch (e) {{
    return "";
  }}
}}

Interceptor.attach(target, {{
  onEnter(args) {{
    const a0 = args[0], a1 = args[1], a2 = args[2];
    const s0 = s8(a0), s1 = s8(a1), s2 = s8(a2);
    const blob = (s0 + " | " + s1 + " | " + s2).toLowerCase();
    const h0 = h(a0), h1 = h(a1), h2 = h(a2);
    const hblob = (h0 + "\\n" + h1 + "\\n" + h2).toLowerCase();
    if (blob.indexOf("message_lookup.db") >= 0 || hblob.indexOf("6d 65 73 73 61 67 65 5f 74 61 62 6c 65") >= 0) {{
      if (blob.indexOf(KEY) >= 0 || hblob.indexOf("73 65 6c 65 63 74 20 73 65 71 75 65 6e 63 65") >= 0) {{
        send({{
          ts: Date.now(),
          ret: this.returnAddress.toString(),
          a0: a0.toString(),
          a1: a1.toString(),
          a2: a2.toString(),
          s0: s0, s1: s1, s2: s2,
          h0: h0, h1: h1, h2: h2,
          bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
            .slice(0, 14)
            .map(DebugSymbol.fromAddress)
            .map(function (x) {{ return x.toString(); }})
        }});
      }}
    }}
  }}
}});
"""
        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") == "send":
                events.append(msg.get("payload", {}))

        script.on("message", on_message)
        script.load()
        time.sleep(max(1, args.duration))
    finally:
        sess.detach()

    payload = {
        "pid": args.pid,
        "addr": args.addr,
        "duration_s": args.duration,
        "query_keyword": args.query_keyword,
        "event_count": len(events),
        "events": events,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
