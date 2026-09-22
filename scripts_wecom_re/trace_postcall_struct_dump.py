"""
改进版 post-call 提取脚本
策略：
  1. Logger 钩子（0xa3616d0）: 当路径含 message_lookup.db → 标记线程(armed)
  2. post-call 钩子（0xb9114b）: 线程 armed → 读取 [ebp+0xC] 结构体（256字节）
  3. 同时做 complete struct dump 来定位 sequence/send_time 字段
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Post-call struct dump for message_lookup sequence/send_time extraction (PID 20632 addresses)"
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--logger-addr", default="0xa3616d0", help="Logger func addr for PID 20632")
    parser.add_argument("--post-addr", default="0xb9114b", help="Post-call instruction addr for PID 20632")
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--max-events", type=int, default=6)
    parser.add_argument("--ttl-ms", type=int, default=2000)
    parser.add_argument("--out", default="runtime/wecom_re/postcall_struct_dump.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const LOGGER = ptr("%LOGGER%");
const POST = ptr("%POST%");
const MAX_EVENTS = %MAX%;
const TTL_MS = %TTL%;
let count = 0;
const armed = new Map(); // tid -> {expires, path, a0ptr, ts}

function u32(p) { try { return p.readU32() >>> 0; } catch (e) { return 0; } }
function u64at(p) {
  try {
    const lo = p.readU32() >>> 0;
    const hi = p.add(4).readU32() >>> 0;
    return { lo: lo, hi: hi,
             hex: "0x" + hi.toString(16).padStart(8,"0") + lo.toString(16).padStart(8,"0"),
             dec: ((BigInt(hi) << 32n) + BigInt(lo)).toString() };
  } catch (e) { return null; }
}
function s8(p, n) { try { const t = p.readCString(); return t ? t.slice(0, n || 150) : ""; } catch (e) { return ""; } }
function hd(p, n) { try { return hexdump(p, {offset:0, length:n, header:false, ansi:false}); } catch (e) { return ""; } }
function looksPtr(v) { return v >= 0x10000 && v < 0x7fff0000; }

function dumpStruct(base, nSlots) {
  const slots = [];
  for (let i = 0; i < nSlots; i++) {
    const off = i * 4;
    const v = u32(base.add(off));
    const slot = { off: off, hex: "0x" + (v >>> 0).toString(16), u32: v };
    slot.u64_here = u64at(base.add(off));
    if (looksPtr(v)) {
      const p = ptr(v);
      slot.s8 = s8(p, 60);
      slot.u64_at = u64at(p);
    }
    slots.push(slot);
  }
  return slots;
}

// === Gate hook at logger ===
Interceptor.attach(LOGGER, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const a0 = args[0];
    const path = s8(a0, 256);
    if (path.indexOf("message_lookup.db") < 0) return;
    const tid = this.threadId;
    const now = Date.now();
    armed.set(tid, {
      expires: now + TTL_MS,
      path: path,
      a0ptr: a0.toString(),
      ts: now,
    });
  }
});

// === Post-call hook ===
Interceptor.attach(POST, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const tid = this.threadId;
    const now = Date.now();
    const gate = armed.get(tid);
    if (!gate) return;
    if (gate.expires < now) { armed.delete(tid); return; }

    armed.delete(tid);

    const ebp = this.context.ebp;
    // Read key stack args from current frame
    const a8 = u32(ebp.add(8));
    const a12 = u32(ebp.add(12));
    const a16 = u32(ebp.add(16));
    const a20 = u32(ebp.add(20));
    const a24 = u32(ebp.add(24));
    const a28 = u32(ebp.add(28));

    // Dump the struct at a12 (message_id at +0, expect sequence/send_time elsewhere)
    let struct_a12 = [];
    let struct_a12_hd = "";
    if (looksPtr(a12)) {
      struct_a12 = dumpStruct(ptr(a12), 32); // 128 bytes = 32 dwords
      struct_a12_hd = hd(ptr(a12), 128);
    }

    // Dump struct at a8 too
    let struct_a8 = [];
    if (looksPtr(a8)) {
      struct_a8 = dumpStruct(ptr(a8), 16);
    }

    // EAX, EBX etc might hold result
    const regs = {
      eax: this.context.eax.toString(),
      ebx: this.context.ebx.toString(),
      ecx: this.context.ecx.toString(),
      edx: this.context.edx.toString(),
      esi: this.context.esi.toString(),
      edi: this.context.edi.toString(),
    };

    count += 1;
    send({
      ts: now,
      tid: tid,
      gate: gate,
      frame_args: { a8: "0x" + (a8>>>0).toString(16), a12: "0x" + (a12>>>0).toString(16),
                    a16: "0x"+(a16>>>0).toString(16), a20: a20, a24: "0x"+(a24>>>0).toString(16), a28: a28 },
      struct_a12: struct_a12,
      struct_a12_hd: struct_a12_hd,
      struct_a8: struct_a8,
      regs: regs,
    });
  }
});
"""
        js = (js
              .replace("%LOGGER%", args.logger_addr)
              .replace("%POST%", args.post_addr)
              .replace("%MAX%", str(max(1, int(args.max_events))))
              .replace("%TTL%", str(max(200, int(args.ttl_ms)))))

        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") == "send":
                events.append(msg.get("payload", {}))
            elif msg.get("type") == "error":
                events.append({"frida_error": msg})

        script.on("message", on_message)
        script.load()
        import sys
        print(f"[*] Hooked logger={args.logger_addr} post={args.post_addr} pid={args.pid}")
        print(f"[*] Waiting {args.duration}s ... trigger: open FTA -> send msg -> return chat -> scroll")
        sys.stdout.flush()
        time.sleep(max(1, args.duration))
    finally:
        # Write output BEFORE detach (detach may hang)
        payload = {
            "pid": args.pid,
            "logger_addr": args.logger_addr,
            "post_addr": args.post_addr,
            "duration_s": args.duration,
            "event_count": len(events),
            "events": events,
        }
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        import sys
        print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))
        sys.stdout.flush()
        try:
            sess.detach()
        except Exception:
            pass

    # payload already written in finally block above


if __name__ == "__main__":
    main()
