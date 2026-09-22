from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace candidate logger and capture interesting strings.")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0", help="Runtime address of candidate logger function.")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--filter", default="db|sqlite|wxwork|message|session|user\\.db|crm\\.db|kv\\.db")
    parser.add_argument("--out", default="runtime/wecom_re/logger_trace.json")
    parser.add_argument("--backtrace-depth", type=int, default=10, help="Frames to capture for matched events.")
    parser.add_argument(
        "--backtracer",
        choices=("fuzzy", "accurate"),
        default="fuzzy",
        help="Backtracer mode for Thread.backtrace().",
    )
    parser.add_argument(
        "--hexdump-len",
        type=int,
        default=0,
        help="If >0, include hexdump for a0/a1/a2 up to this byte length.",
    )
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    pat = re.compile(args.filter, re.IGNORECASE)

    events: list[dict] = []
    sess = frida.attach(args.pid)
    try:
        js = f"""
const target = ptr("{args.addr}");
const BT_DEPTH = {max(1, int(args.backtrace_depth))};
const BT_MODE = "{args.backtracer}" === "accurate" ? Backtracer.ACCURATE : Backtracer.FUZZY;
const HEX_LEN = {max(0, int(args.hexdump_len))};
function s8(p) {{ try {{ return p.readCString(); }} catch (e) {{ return ""; }} }}
function s16(p) {{ try {{ return p.readUtf16String(); }} catch (e) {{ return ""; }} }}
function hd(p) {{
  if (HEX_LEN <= 0) return "";
  try {{
    return hexdump(p, {{ offset: 0, length: HEX_LEN, header: false, ansi: false }});
  }} catch (e) {{
    return "";
  }}
}}
Interceptor.attach(target, {{
  onEnter(args) {{
    const a0 = args[0];
    const a1 = args[1];
    const a2 = args[2];
    send({{
      ts: Date.now(),
      ret: this.returnAddress.toString(),
      a0: a0.toString(),
      a1: a1.toString(),
      a2: a2.toString(),
      s0: s8(a0),
      s1: s8(a1),
      s2: s8(a2),
      u0: s16(a0),
      u1: s16(a1),
      u2: s16(a2),
      h0: hd(a0),
      h1: hd(a1),
      h2: hd(a2),
      bt: Thread.backtrace(this.context, BT_MODE)
        .slice(0, BT_DEPTH)
        .map(DebugSymbol.fromAddress)
        .map(function (s) {{ return s.toString(); }})
    }});
  }}
}});
"""
        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") != "send":
                return
            p = msg.get("payload", {})
            blob = " | ".join(
                str(p.get(k, "")) for k in ("s0", "s1", "s2", "u0", "u1", "u2")
            )
            if pat.search(blob):
                events.append(p)

        script.on("message", on_message)
        script.load()
        time.sleep(max(1, args.duration))
    finally:
        sess.detach()

    out.write_text(
        json.dumps(
            {
                "pid": args.pid,
                "addr": args.addr,
                "duration_s": args.duration,
                "filter": args.filter,
                "event_count": len(events),
                "events": events,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
