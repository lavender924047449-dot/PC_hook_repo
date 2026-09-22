from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="On message_lookup SQL logger hit, walk EBP frames and dump integer/pointer args."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--max-events", type=int, default=6)
    parser.add_argument("--frames", type=int, default=10)
    parser.add_argument("--out", default="runtime/wecom_re/lookup_ebp_walk.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const target = ptr("%ADDR%");
const MAX_EVENTS = %MAX%;
const FRAMES = %FRAMES%;
let count = 0;

function u32(p) { try { return p.readU32() >>> 0; } catch (e) { return 0; } }
function s8(p) { try { const t = p.readCString(); return t ? t.slice(0, 120) : ""; } catch (e) { return ""; } }
function hd(p, n) {
  try { return hexdump(p, { offset: 0, length: n, header: false, ansi: false }); }
  catch (e) { return ""; }
}
function looksPtr(v) { return v >= 0x10000 && v < 0x7fff0000; }
function asU64(p) {
  try {
    const lo = p.readU32() >>> 0;
    const hi = p.add(4).readU32() >>> 0;
    const dec = ((BigInt(hi) << 32n) + BigInt(lo)).toString();
    return { hex: "0x" + hi.toString(16).padStart(8, "0") + lo.toString(16).padStart(8, "0"), dec: dec, lo: lo, hi: hi };
  } catch (e) { return { hex: "", dec: "", lo: 0, hi: 0 }; }
}
function decode(v) {
  const rec = { hex: "0x" + (v >>> 0).toString(16), u32: v >>> 0, s8: "", u64: null, hd: "" };
  if (!looksPtr(v)) return rec;
  const p = ptr(v);
  rec.s8 = s8(p);
  rec.u64 = asU64(p);
  rec.hd = hd(p, 24);
  return rec;
}

Interceptor.attach(target, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const a0 = args[0];
    let hay = "";
    try { hay = hexdump(a0, { offset: 0, length: 220, header: false, ansi: false }).toLowerCase(); }
    catch (e) { return; }
    if (hay.indexOf("73 65 6c 65 63 74 20 73 65 71 75 65 6e 63 65") < 0) return;
    if (hay.indexOf("6d 65 73 73 61 67 65 5f 74 61 62 6c 65") < 0) return;
    count += 1;

    const ctx = this.context;
    const regs = {
      eax: ctx.eax.toString(), ebx: ctx.ebx.toString(), ecx: ctx.ecx.toString(),
      edx: ctx.edx.toString(), esi: ctx.esi.toString(), edi: ctx.edi.toString(),
      ebp: ctx.ebp.toString(), esp: ctx.esp.toString()
    };
    const reg_decoded = {
      ebx: decode(ctx.ebx.toInt32() >>> 0),
      esi: decode(ctx.esi.toInt32() >>> 0),
      edi: decode(ctx.edi.toInt32() >>> 0),
      ecx: decode(ctx.ecx.toInt32() >>> 0)
    };

    const frames = [];
    let ebp = ctx.ebp;
    for (let i = 0; i < FRAMES; i++) {
      const saved = ptr(u32(ebp));
      const ret = u32(ebp.add(4));
      const a = [];
      for (let k = 2; k <= 8; k++) {
        a.push({ off: k * 4, ...decode(u32(ebp.add(k * 4))) });
      }
      frames.push({
        i: i,
        ebp: ebp.toString(),
        ret: "0x" + ret.toString(16),
        args: a
      });
      if (!looksPtr(saved.toInt32() >>> 0)) break;
      if (saved.toInt32() >>> 0 <= ebp.toInt32() >>> 0) break;
      ebp = saved;
    }

    send({
      ts: Date.now(),
      ret: this.returnAddress.toString(),
      regs: regs,
      reg_decoded: reg_decoded,
      frames: frames,
      path: s8(a0)
    });
  }
});
"""
        js = (
            js.replace("%ADDR%", args.addr)
            .replace("%MAX%", str(max(1, int(args.max_events))))
            .replace("%FRAMES%", str(max(3, int(args.frames))))
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
        "duration_s": args.duration,
        "event_count": len(events),
        "events": events,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
