from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hook GetMessageSequenceAndTime (message_storage dispatcher case 2) to recover bind/result integers."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument(
        "--addr",
        default="0x8e3b4c2",
        help="Runtime VA of message_storage dispatcher (switch on [ebp+0x14]).",
    )
    parser.add_argument("--case", type=int, default=2, help="Switch case for GetMessageSequenceAndTime.")
    parser.add_argument("--duration", type=int, default=150)
    parser.add_argument("--max-events", type=int, default=12)
    parser.add_argument("--out", default="runtime/wecom_re/get_message_sequence_trace.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const target = ptr("%ADDR%");
const WANT_CASE = %CASE%;
const MAX_EVENTS = %MAX%;
let count = 0;

function u32(p) { try { return p.readU32() >>> 0; } catch (e) { return 0; } }
function s8(p) { try { const t = p.readCString(); return t ? t.slice(0, 160) : ""; } catch (e) { return ""; } }
function hd(p, n) {
  try { return hexdump(p, { offset: 0, length: n, header: false, ansi: false }); }
  catch (e) { return ""; }
}
function looksPtr(v) { return v >= 0x10000 && v < 0x7fff0000; }
function decodeVal(v) {
  const rec = {
    u32: v >>> 0,
    hex: "0x" + (v >>> 0).toString(16),
    s8: "",
    u64_le: "",
    hd: ""
  };
  if (!looksPtr(v)) return rec;
  const p = ptr(v);
  rec.s8 = s8(p);
  try {
    const lo = p.readU32() >>> 0;
    const hi = p.add(4).readU32() >>> 0;
    rec.u64_le = "0x" + hi.toString(16).padStart(8, "0") + lo.toString(16).padStart(8, "0");
    rec.u64_dec = ((BigInt(hi) << 32n) + BigInt(lo)).toString();
  } catch (e) {}
  rec.hd = hd(p, 32);
  return rec;
}
function snapArgs(ctx) {
  const ecx = ctx.ecx.toInt32() >>> 0;
  const slots = [];
  for (let i = 1; i <= 8; i++) {
    const raw = u32(ctx.esp.add(i * 4));
    slots.push({ esp_off: i * 4, ...decodeVal(raw) });
  }
  return { ecx: "0x" + ecx.toString(16), ecx_hd: hd(ptr(ecx), 48), stack: slots };
}

Interceptor.attach(target, {
  onEnter(args) {
    const opcode = u32(this.context.esp.add(16)); // [esp+0x10] = 4th stack arg before prologue
    if (opcode !== WANT_CASE) return;
    if (count >= MAX_EVENTS) return;
    this.hit = true;
    count += 1;
    this.snap_in = snapArgs(this.context);
    this.retaddr = this.returnAddress.toString();
    this.ts_in = Date.now();
  },
  onLeave(retval) {
    if (!this.hit) return;
    const out_slots = [];
    // Re-read the same stack slots; output pointers should now be populated.
    try {
      for (let i = 0; i < this.snap_in.stack.length; i++) {
        const rec = this.snap_in.stack[i];
        if (!rec.hex || rec.hex === "0x0") {
          out_slots.push({ esp_off: rec.esp_off, in: rec, out: rec });
          continue;
        }
        const v = rec.u32 >>> 0;
        out_slots.push({ esp_off: rec.esp_off, in: rec, out: decodeVal(v) });
      }
    } catch (e) {}
    send({
      ts_in: this.ts_in,
      ts_out: Date.now(),
      ret: this.retaddr,
      eax: retval.toString(),
      in: this.snap_in,
      out_slots: out_slots
    });
  }
});
"""
        js = (
            js.replace("%ADDR%", args.addr)
            .replace("%CASE%", str(int(args.case)))
            .replace("%MAX%", str(max(1, int(args.max_events))))
        )
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
        "case": args.case,
        "duration_s": args.duration,
        "event_count": len(events),
        "events": events,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
