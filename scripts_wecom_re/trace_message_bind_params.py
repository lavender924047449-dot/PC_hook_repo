from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gated logger trace: recover bind params / nearby pointers for message_table lookup SQL."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--out", default="runtime/wecom_re/message_bind_params.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const target = ptr("%ADDR%");
const SQL_HEX = "73 65 6c 65 63 74 20 73 65 71 75 65 6e 63 65";
const TABLE_HEX = "6d 65 73 73 61 67 65 5f 74 61 62 6c 65";

function s8(p) { try { const t = p.readCString(); return t ? t : ""; } catch (e) { return ""; } }
function s16(p) { try { const t = p.readUtf16String(); return t ? t : ""; } catch (e) { return ""; } }
function u32(p) { try { return p.readU32(); } catch (e) { return 0; } }
function hd(p, n) {
  try { return hexdump(p, { offset: 0, length: n, header: false, ansi: false }); }
  catch (e) { return ""; }
}
function looksPtr(v) {
  return v >= 0x10000 && v < 0x7fff0000;
}
function followPtr(v) {
  if (!looksPtr(v)) return { va: "0x" + v.toString(16), s8: "", s16: "", u32: 0 };
  const p = ptr(v);
  return { va: p.toString(), s8: s8(p).slice(0, 180), s16: s16(p).slice(0, 180), u32: u32(p) };
}
function stackSlots(ctx, n) {
  const out = [];
  try {
    const esp = ctx.esp;
    for (let i = 0; i < n; i++) {
      const slot = esp.add(i * 4);
      const v = u32(slot);
      const f = followPtr(v);
      out.push({ off: i * 4, raw: "0x" + v.toString(16), ...f });
    }
  } catch (e) {}
  return out;
}
function nearbyPtrs(base, bytes) {
  const out = [];
  try {
    for (let i = 0; i < bytes; i += 4) {
      const v = u32(base.add(i));
      if (!looksPtr(v)) continue;
      const f = followPtr(v);
      if ((f.s8 && f.s8.length >= 4) || (f.s16 && f.s16.length >= 4)) {
        out.push({ off: i, ...f });
      }
    }
  } catch (e) {}
  return out.slice(0, 24);
}

Interceptor.attach(target, {
  onEnter(args) {
    const a0 = args[0], a1 = args[1], a2 = args[2], a3 = args[3];
    const s0 = s8(a0), s1 = s8(a1), s2 = s8(a2);
    const h0 = hd(a0, 384);
    const h1 = hd(a1, 256);
    const blob = (s0 + "\n" + s1 + "\n" + h0 + "\n" + h1).toLowerCase();
    if (blob.indexOf("message_lookup.db") < 0 && blob.indexOf(TABLE_HEX) < 0) return;
    if (blob.indexOf(SQL_HEX) < 0 && blob.indexOf("message_id") < 0) return;

    send({
      ts: Date.now(),
      ret: this.returnAddress.toString(),
      a0: a0.toString(),
      a1: a1.toString(),
      a2: a2.toString(),
      a3: a3.toString(),
      s0: s0,
      s1: s1,
      s2: s2,
      s3: s8(a3),
      h0: h0,
      h1: h1,
      h2: hd(a2, 160),
      nearby_a0: nearbyPtrs(a0, 256),
      nearby_a1: nearbyPtrs(a1, 160),
      nearby_a2: nearbyPtrs(a2, 96),
      stack: stackSlots(this.context, 16),
      bt: Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 12)
        .map(DebugSymbol.fromAddress)
        .map(function (x) { return x.toString(); })
    });
  }
});
""".replace("%ADDR%", args.addr)
        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") == "send":
                events.append(msg.get("payload", {}))
            elif msg.get("type") == "error":
                events.append({"error": msg})

        script.on("message", on_message)
        script.load()
        time.sleep(max(1, args.duration))
    finally:
        sess.detach()

    payload = {
        "pid": args.pid,
        "addr": args.addr,
        "duration_s": args.duration,
        "event_count": len(events),
        "events": events,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
