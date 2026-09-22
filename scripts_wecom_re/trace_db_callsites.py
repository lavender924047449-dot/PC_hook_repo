from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


DEFAULT_SITES = [
    "0x51fa504",  # message.db candidate
    "0x51fa6c8",  # user.db candidate
    "0x51fa88c",  # session.db candidate
    "0x9714c1f",  # file.db candidate
    "0x9714d24",  # user.db candidate
    "0x970bf4e",  # kv.db candidate
    "0x970cfae",
    "0x970fca4",
    "0x97109c6",
    "0x9718870",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace DB-related callsites in WXWork and dump JSON events.")
    parser.add_argument("--pid", type=int, required=True, help="Target WXWork PID.")
    parser.add_argument("--duration", type=int, default=120, help="Trace duration in seconds.")
    parser.add_argument("--out", default="runtime/wecom_re/db_callsites_trace.json", help="Output JSON path.")
    parser.add_argument("--sites", default=",".join(DEFAULT_SITES), help="Comma-separated runtime addresses.")
    args = parser.parse_args()

    sites = [x.strip() for x in args.sites.split(",") if x.strip()]
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = f"""
const SITES = {json.dumps(sites)}.map(ptr);
function safeAnsi(p) {{
  try {{ return p.readCString(); }} catch (e) {{ return ""; }}
}}
function safeU16(p) {{
  try {{ return p.readUtf16String(); }} catch (e) {{ return ""; }}
}}
for (const s of SITES) {{
  Interceptor.attach(s, {{
    onEnter(args) {{
      try {{
        const a0 = Memory.readPointer(this.context.esp);
        const a1 = Memory.readPointer(this.context.esp.add(4));
        const a2 = Memory.readPointer(this.context.esp.add(8));
        send({{
          ts: Date.now(),
          site: s.toString(),
          a0: a0.toString(),
          a1: a1.toString(),
          a2: a2.toString(),
          s0: safeAnsi(a0),
          s1: safeAnsi(a1),
          s2: safeAnsi(a2),
          u0: safeU16(a0),
          u1: safeU16(a1),
          u2: safeU16(a2),
        }});
      }} catch (e) {{
        send({{ ts: Date.now(), site: s.toString(), error: String(e) }});
      }}
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
        "duration_s": args.duration,
        "sites": sites,
        "event_count": len(events),
        "events": events,
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out_path), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
