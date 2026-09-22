from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="On message_lookup SQL hit: dump post-SQL integers, EBP args, and pointers to SQL text."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0")
    parser.add_argument("--duration", type=int, default=180)
    parser.add_argument("--max-events", type=int, default=8)
    parser.add_argument("--out", default="runtime/wecom_re/lookup_bind_deep.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const target = ptr("%ADDR%");
const MAX_EVENTS = %MAX%;
let count = 0;

function u32(p) { try { return p.readU32() >>> 0; } catch (e) { return 0; } }
function s8(p) { try { const t = p.readCString(); return t ? t.slice(0, 140) : ""; } catch (e) { return ""; } }
function hd(p, n) {
  try { return hexdump(p, { offset: 0, length: n, header: false, ansi: false }); }
  catch (e) { return ""; }
}
function looksPtr(v) { return v >= 0x10000 && v < 0x7fff0000; }
function u64dec(p) {
  try {
    const lo = p.readU32() >>> 0;
    const hi = p.add(4).readU32() >>> 0;
    return { hex: "0x" + hi.toString(16).padStart(8,"0") + lo.toString(16).padStart(8,"0"),
             dec: ((BigInt(hi) << 32n) + BigInt(lo)).toString(), lo: lo, hi: hi };
  } catch (e) { return null; }
}
function decode(v) {
  const rec = { hex: "0x" + (v>>>0).toString(16), u32: v>>>0, s8: "", u64: null };
  if (!looksPtr(v)) return rec;
  const p = ptr(v);
  rec.s8 = s8(p);
  rec.u64 = u64dec(p);
  return rec;
}

Interceptor.attach(target, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const a0 = args[0];
    const path = s8(a0);
    if (path.indexOf("message_lookup.db") < 0) return;
    let h0 = "";
    try { h0 = hexdump(a0, { offset: 0, length: 320, header: false, ansi: false }); }
    catch (e) { h0 = ""; }
    count += 1;

    const sqlOff = s8(a0).length + 1;
    // SQL often sits after path NUL + small header. Search for 'select sequence'
    let sqlPtr = null;
    try {
      const raw = a0.readByteArray(384);
      const bytes = new Uint8Array(raw);
      const needle = [0x73,0x65,0x6c,0x65,0x63,0x74,0x20,0x73,0x65,0x71,0x75,0x65,0x6e,0x63,0x65];
      for (let i = 0; i < bytes.length - needle.length; i++) {
        let ok = true;
        for (let j = 0; j < needle.length; j++) { if (bytes[i+j] !== needle[j]) { ok = false; break; } }
        if (ok) { sqlPtr = a0.add(i); break; }
      }
    } catch (e) {}

    const after_sql = [];
    if (sqlPtr) {
      const end = sqlPtr.add(s8(sqlPtr).length + 1);
      for (let i = 0; i < 48; i++) {
        const p = end.add(i * 4);
        const v = u32(p);
        after_sql.push({ off: i * 4, ...decode(v), u64_here: u64dec(p) });
      }
    }

    const ctx = this.context;
    const frames = [];
    let ebp = ctx.ebp;
    for (let i = 0; i < 8; i++) {
      const argsx = [];
      for (let k = 2; k <= 7; k++) argsx.push({ off: k*4, ...decode(u32(ebp.add(k*4))) });
      frames.push({ i: i, ebp: ebp.toString(), ret: "0x" + u32(ebp.add(4)).toString(16), args: argsx });
      const nxt = u32(ebp);
      if (!looksPtr(nxt) || nxt <= (ebp.toInt32()>>>0)) break;
      ebp = ptr(nxt);
    }

    const regs = ["ebx","esi","edi","ecx","edx","eax"].map(function (n) {
      const v = ctx[n].toInt32() >>> 0;
      return { reg: n, ...decode(v) };
    });

    send({
      ts: Date.now(),
      ret: this.returnAddress.toString(),
      path: s8(a0),
      sql: sqlPtr ? s8(sqlPtr) : "",
      sql_ptr: sqlPtr ? sqlPtr.toString() : "",
      after_sql: after_sql,
      regs: regs,
      frames: frames,
      h0: h0
    });
  }
});
"""
        js = js.replace("%ADDR%", args.addr).replace("%MAX%", str(max(1, int(args.max_events))))
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
