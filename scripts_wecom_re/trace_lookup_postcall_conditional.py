from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Conditional post-call capture: gate 0xE6114B by message_lookup SQL hit at logger."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--logger-addr", default="0xa6316d0")
    parser.add_argument("--post-addr", default="0xe6114b")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--max-events", type=int, default=8)
    parser.add_argument("--ttl-ms", type=int, default=1500)
    parser.add_argument("--out", default="runtime/wecom_re/lookup_postcall_conditional.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r'''
const LOGGER = ptr("%LOGGER%");
const POST = ptr("%POST%");
const MAX_EVENTS = %MAX%;
const TTL_MS = %TTL%;
let count = 0;
const armed = new Map(); // tid -> {expires,path,sql,ret,ts}

function u32(p) { try { return p.readU32() >>> 0; } catch (e) { return 0; } }
function s8(p, n) { try { const t = p.readCString(); return t ? t.slice(0, n || 120) : ""; } catch (e) { return ""; } }
function hd(p, n) {
  try { return hexdump(p, { offset: 0, length: n, header: false, ansi: false }); }
  catch (e) { return ""; }
}
function looksPtr(v) { return v >= 0x10000 && v < 0x7fff0000; }
function u64At(p) {
  try {
    const lo = p.readU32() >>> 0;
    const hi = p.add(4).readU32() >>> 0;
    return {
      hex: "0x" + hi.toString(16).padStart(8, "0") + lo.toString(16).padStart(8, "0"),
      dec: ((BigInt(hi) << 32n) + BigInt(lo)).toString(),
      lo: lo,
      hi: hi,
    };
  } catch (e) {
    return null;
  }
}
function decodePtr(v) {
  const rec = { hex: "0x" + (v >>> 0).toString(16), u32: v >>> 0, s8: "", u64: null, hd: "" };
  if (!looksPtr(v)) return rec;
  const p = ptr(v);
  rec.s8 = s8(p, 120);
  rec.u64 = u64At(p);
  rec.hd = hd(p, 64);
  return rec;
}
function parseSqlFromA0(a0) {
  try {
    const raw = a0.readByteArray(512);
    const bytes = new Uint8Array(raw);
    const needle = [0x73,0x65,0x6c,0x65,0x63,0x74,0x20,0x73,0x65,0x71,0x75,0x65,0x6e,0x63,0x65]; // select sequence
    for (let i = 0; i < bytes.length - needle.length; i++) {
      let ok = true;
      for (let j = 0; j < needle.length; j++) {
        if (bytes[i + j] !== needle[j]) { ok = false; break; }
      }
      if (ok) {
        const sp = a0.add(i);
        return { ptr: sp.toString(), sql: s8(sp, 220) };
      }
    }
  } catch (e) {}
  return { ptr: "", sql: "" };
}

Interceptor.attach(LOGGER, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const a0 = args[0];
    const path = s8(a0, 200);
    if (path.indexOf("message_lookup.db") < 0) return;
    const parsed = parseSqlFromA0(a0);
    if (parsed.sql.indexOf("select sequence") < 0 || parsed.sql.indexOf("message_id = ?") < 0) return;
    const tid = this.threadId;
    const now = Date.now();
    armed.set(tid, {
      expires: now + TTL_MS,
      path: path,
      sql: parsed.sql,
      sql_ptr: parsed.ptr,
      logger_ret: this.returnAddress.toString(),
      logger_ts: now,
    });
  }
});

Interceptor.attach(POST, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const tid = this.threadId;
    const now = Date.now();
    const gate = armed.get(tid);
    if (!gate) return;
    if (gate.expires < now) {
      armed.delete(tid);
      return;
    }

    const esp = this.context.esp;
    const ebp = this.context.ebp;
    const a_esp0 = u32(esp);
    const a_esp4 = u32(esp.add(4));
    const a_esp8 = u32(esp.add(8));
    const a_espC = u32(esp.add(12));

    const outBlob = [];
    if (looksPtr(a_espC)) {
      const p = ptr(a_espC);
      for (let i = 0; i < 24; i++) {
        const slot = p.add(i * 4);
        outBlob.push({
          off: i * 4,
          dword_hex: "0x" + u32(slot).toString(16),
          qword: u64At(slot),
        });
      }
    }

    count += 1;
    send({
      ts: now,
      tid: tid,
      gate: gate,
      post_addr: POST.toString(),
      regs: {
        eax: this.context.eax.toString(),
        ebx: this.context.ebx.toString(),
        ecx: this.context.ecx.toString(),
        edx: this.context.edx.toString(),
        esi: this.context.esi.toString(),
        edi: this.context.edi.toString(),
        ebp: ebp.toString(),
        esp: esp.toString(),
      },
      stack_args: {
        esp_0: decodePtr(a_esp0),
        esp_4: decodePtr(a_esp4),
        esp_8: decodePtr(a_esp8),
        esp_c: decodePtr(a_espC),
      },
      ebp_slots: {
        ebp_m20: decodePtr(u32(ebp.sub(0x20))),
        ebp_m1c: decodePtr(u32(ebp.sub(0x1c))),
        ebp_p8: decodePtr(u32(ebp.add(8))),
        ebp_pC: decodePtr(u32(ebp.add(0xC))),
        ebp_p10: decodePtr(u32(ebp.add(0x10))),
      },
      out_blob_from_esp_c: outBlob,
      esp_hd: hd(esp, 96),
    });

    armed.delete(tid);
  }
});
'''
        js = (
            js.replace("%LOGGER%", args.logger_addr)
            .replace("%POST%", args.post_addr)
            .replace("%MAX%", str(max(1, int(args.max_events))))
            .replace("%TTL%", str(max(200, int(args.ttl_ms))))
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
        "logger_addr": args.logger_addr,
        "post_addr": args.post_addr,
        "duration_s": args.duration,
        "event_count": len(events),
        "events": events,
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
