from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture stack/context around message_lookup SQL query events.")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0", help="Logger function runtime address.")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--max-events", type=int, default=12)
    parser.add_argument("--hexdump-len", type=int, default=224)
    parser.add_argument("--out", default="runtime/wecom_re/message_lookup_context_trace.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = f"""
const target = ptr("{args.addr}");
const HEX_LEN = {max(64, int(args.hexdump_len))};
const MAX_EVENTS = {max(1, int(args.max_events))};
let count = 0;

function s8(p) {{ try {{ return p.readCString(); }} catch (e) {{ return ""; }} }}
function s16(p) {{ try {{ return p.readUtf16String(); }} catch (e) {{ return ""; }} }}
function hd(p, n) {{
  try {{
    return hexdump(p, {{ offset: 0, length: n, header: false, ansi: false }});
  }} catch (e) {{
    return "";
  }}
}}

function stackSnapshot(esp) {{
  const rows = [];
  for (let i = 0; i < 40; i++) {{
    const p = esp.add(i * 4);
    let v = ptr("0");
    try {{ v = Memory.readPointer(p); }} catch (e) {{}}
    const rec = {{
      off: i * 4,
      ptr: v.toString(),
      s8: "",
      s16: "",
      qword: "",
      hd: ""
    }};
    try {{
      rec.s8 = s8(v);
      rec.s16 = s16(v);
      rec.hd = hd(v, 48);
    }} catch (e) {{}}
    try {{
      const lo = Memory.readU32(v);
      const hi = Memory.readU32(v.add(4));
      rec.qword = "0x" + hi.toString(16).padStart(8, "0") + lo.toString(16).padStart(8, "0");
    }} catch (e) {{}}
    rows.push(rec);
  }}
  return rows;
}}

Interceptor.attach(target, {{
  onEnter(args) {{
    if (count >= MAX_EVENTS) return;
    const a0 = args[0], a1 = args[1], a2 = args[2];
    const h0 = hd(a0, HEX_LEN), h1 = hd(a1, HEX_LEN), h2 = hd(a2, HEX_LEN);
    const hay = (h0 + "\\n" + h1 + "\\n" + h2).toLowerCase();
    if (hay.indexOf("73 65 6c 65 63 74 20 73 65 71 75 65 6e 63 65") < 0) return;
    if (hay.indexOf("6d 65 73 73 61 67 65 5f 74 61 62 6c 65") < 0) return;
    count += 1;
    send({{
      ts: Date.now(),
      ret: this.returnAddress.toString(),
      regs: {{
        eax: this.context.eax.toString(),
        ebx: this.context.ebx.toString(),
        ecx: this.context.ecx.toString(),
        edx: this.context.edx.toString(),
        esi: this.context.esi.toString(),
        edi: this.context.edi.toString(),
        ebp: this.context.ebp.toString(),
        esp: this.context.esp.toString(),
      }},
      a0: a0.toString(),
      a1: a1.toString(),
      a2: a2.toString(),
      s0: s8(a0),
      s1: s8(a1),
      s2: s8(a2),
      h0: h0,
      h1: h1,
      h2: h2,
      stack: stackSnapshot(this.context.esp),
      bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 16)
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
