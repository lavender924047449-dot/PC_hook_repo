from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode a2 context structure for message_lookup SQL events.")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0")
    parser.add_argument("--duration", type=int, default=150)
    parser.add_argument("--max-events", type=int, default=6)
    parser.add_argument("--out", default="runtime/wecom_re/message_lookup_struct_trace.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = f"""
const target = ptr("{args.addr}");
const MAX_EVENTS = {max(1, int(args.max_events))};
let count = 0;

function s8(p) {{ try {{ return p.readCString(); }} catch (e) {{ return ""; }} }}
function s16(p) {{ try {{ return p.readUtf16String(); }} catch (e) {{ return ""; }} }}
function hd(p, n) {{
  try {{ return hexdump(p, {{ offset: 0, length: n, header: false, ansi: false }}); }}
  catch (e) {{ return ""; }}
}}

function decodeCtx(ptrCtx) {{
  const rows = [];
  for (let i = 0; i < 40; i++) {{
    const off = i * 4;
    const p = ptrCtx.add(off);
    let u32 = 0;
    try {{
      u32 = Memory.readU32(p) >>> 0;
    }} catch (e) {{}}
    let val = ptr("0");
    try {{
      val = ptr("0x" + u32.toString(16));
    }} catch (e) {{}}
    const rec = {{
      off: off,
      u32: "0x" + u32.toString(16),
      as_ptr: val.toString(),
      ptr_s8: "",
      ptr_s16: "",
      ptr_hd: ""
    }};
    if (u32 > 0x10000 && u32 < 0x7fffffff) {{
      rec.ptr_s8 = s8(val);
      rec.ptr_s16 = s16(val);
      rec.ptr_hd = hd(val, 64);
    }}
    rows.push(rec);
  }}
  return rows;
}}

Interceptor.attach(target, {{
  onEnter(args) {{
    if (count >= MAX_EVENTS) return;
    const a0 = args[0], a1 = args[1], a2 = args[2];
    const h0 = hd(a0, 192), h1 = hd(a1, 192);
    const hay = (h0 + "\\n" + h1).toLowerCase();
    if (hay.indexOf("73 65 6c 65 63 74 20 73 65 71 75 65 6e 63 65") < 0) return;
    if (hay.indexOf("6d 65 73 73 61 67 65 5f 74 61 62 6c 65") < 0) return;
    count += 1;
    send({{
      ts: Date.now(),
      ret: this.returnAddress.toString(),
      a0: a0.toString(),
      a1: a1.toString(),
      a2: a2.toString(),
      s0: s8(a0),
      h1: h1,
      a2_hd: hd(a2, 256),
      a2_decoded: decodeCtx(a2),
      bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 14)
        .map(DebugSymbol.fromAddress)
        .map(function (x) {{ return x.toString(); }})
    }});
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
        "max_events": args.max_events,
        "event_count": len(events),
        "events": events,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
