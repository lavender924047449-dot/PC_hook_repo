from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded trace for upstream candidate addresses.")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--targets", default="0x8f38d57,0x8f35929,0x8ebb258")
    parser.add_argument("--duration", type=int, default=40)
    parser.add_argument("--max-events", type=int, default=400)
    parser.add_argument("--out", default="runtime/wecom_re/upstream_candidates_trace.json")
    args = parser.parse_args()

    targets = [x.strip() for x in args.targets.split(",") if x.strip()]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = f"""
const TARGETS = {json.dumps(targets)}.map(ptr);
const MAX_EVENTS = {max(1, int(args.max_events))};
let count = 0;

function s(p) {{ try {{ return p.readCString(); }} catch (e) {{ return ""; }} }}
function h(p) {{
  try {{ return hexdump(p, {{ offset: 0, length: 96, header: false, ansi: false }}); }}
  catch (e) {{ return ""; }}
}}

for (const t of TARGETS) {{
  Interceptor.attach(t, {{
    onEnter(args) {{
      if (count >= MAX_EVENTS) return;
      count += 1;
      send({{
        t: t.toString(),
        a0: args[0].toString(),
        a1: args[1].toString(),
        a2: args[2].toString(),
        s0: s(args[0]),
        s1: s(args[1]),
        s2: s(args[2]),
        h1: h(args[1]),
      }});
    }}
  }});
}}
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
        "targets": targets,
        "duration_s": args.duration,
        "max_events": args.max_events,
        "event_count": len(events),
        "events": events,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
