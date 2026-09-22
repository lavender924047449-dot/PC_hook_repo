"""
策略：通过 Frida MemoryAccessMonitor 监视 a12 struct 内存写入，
当 struct 被写入时捕获 sequence/send_time。

同时结合 logger gate，确保只监视 message_lookup.db 相关的 struct。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Memory watch for struct write after message_lookup query")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--logger-addr", default="0xa3616d0")
    parser.add_argument("--duration", type=int, default=90)
    parser.add_argument("--max-events", type=int, default=8)
    parser.add_argument("--out", default="runtime/wecom_re/memwatch_result.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const LOGGER = ptr("%LOGGER%");
const MAX_EVENTS = %MAX%;
let count = 0;
let watching = null; // {ptr, page_start, page_size, message_id, ts}
let monitorActive = false;

function u32(p) { try { return p.readU32()>>>0; } catch(e){ return 0; } }
function s8(p, n) { try { const t=p.readCString(); return t?t.slice(0,n||200):""; } catch(e){ return ""; } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return ""; } }
function looksPtr(v) { return v>=0x10000 && v<0x7fff0000; }
function u64at(p) {
  try {
    const lo=p.readU32()>>>0, hi=p.add(4).readU32()>>>0;
    return {lo:lo, hi:hi, dec: ((BigInt(hi)<<32n)+BigInt(lo)).toString()};
  } catch(e) { return null; }
}

function dumpStruct(base, n) {
  const rows = [];
  for (let i = 0; i < n; i++) {
    const off = i*4;
    const v = u32(base.add(off));
    const r = {off:off, hex:"0x"+v.toString(16), u32:v};
    r.u64_here = u64at(base.add(off));
    rows.push(r);
  }
  return rows;
}

function stopWatch() {
  if (monitorActive) {
    try { MemoryAccessMonitor.disable(); } catch(e) {}
    monitorActive = false;
  }
  watching = null;
}

function startWatch(structPtr, messageId, ts) {
  if (monitorActive) stopWatch();
  
  const page = Process.pageSize;
  // Page-align the struct address
  const base = structPtr.and(ptr(~(page-1)));
  const end = structPtr.add(128).and(ptr(~(page-1))).add(page);
  const pagesCount = Math.max(1, end.sub(base).toInt32() / page);
  
  watching = {ptr: structPtr, message_id: messageId, ts: ts};
  
  const ranges = [];
  for (let i = 0; i < pagesCount; i++) {
    ranges.push({base: base.add(i*page), size: page});
  }
  
  try {
    MemoryAccessMonitor.enable(ranges, {
      onAccess(details) {
        if (count >= MAX_EVENTS) return;
        if (!watching) return;
        if (details.operation !== 'write') return;
        
        // Read current struct content
        const structNow = dumpStruct(watching.ptr, 24);
        
        // Check if interesting data was written (non-zero values at small offsets)
        let hasNewData = false;
        for (const slot of structNow.slice(1, 8)) {
          if (slot.u32 !== 0) { hasNewData = true; break; }
        }
        if (!hasNewData) return;
        
        count += 1;
        const snap = {
          ts: Date.now(),
          ts_logger: watching.ts,
          msg_id: watching.message_id,
          struct_ptr: watching.ptr.toString(),
          struct_after_write: structNow,
          struct_hd: hd(watching.ptr, 128),
          access_op: details.operation,
          access_from: details.from.toString(),
          access_address: details.address.toString(),
        };
        send(snap);
        stopWatch();
      }
    });
    monitorActive = true;
    
    // Auto-cancel after 3 seconds
    setTimeout(function() {
      if (monitorActive) stopWatch();
    }, 3000);
    
  } catch(e) {
    send({watch_error: e.message});
  }
}

Interceptor.attach(LOGGER, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const path = s8(args[0], 256);
    if (path.indexOf("message_lookup.db") < 0) return;
    
    // Find the a12 struct via EBP walk
    let ebp = this.context.ebp;
    for (let i = 0; i < 7; i++) {
      const ret = u32(ebp.add(4));
      if (ret === 0xb9114b || ret === 0xe6114b) {
        const a12 = u32(ebp.add(12));
        if (!looksPtr(a12)) break;
        const msgId = u32(ptr(a12));
        // Check message_id range
        if (msgId > 180000000 && msgId < 350000000) {
          // This looks like a real message_id - watch this struct
          const preSnapshot = dumpStruct(ptr(a12), 16);
          send({
            type: "armed",
            a12: "0x" + (a12>>>0).toString(16),
            msg_id: msgId,
            struct_pre: preSnapshot,
            hd_pre: hd(ptr(a12), 64),
          });
          startWatch(ptr(a12), msgId, Date.now());
        }
        break;
      }
      const nxt = u32(ebp);
      if (!looksPtr(nxt) || nxt <= (ebp.toInt32()>>>0)) break;
      ebp = ptr(nxt);
    }
  }
});
"""
        js = (js
              .replace("%LOGGER%", args.logger_addr)
              .replace("%MAX%", str(max(1, args.max_events))))

        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") == "send":
                events.append(msg.get("payload", {}))
            elif msg.get("type") == "error":
                events.append({"frida_error": msg})

        script.on("message", on_message)
        script.load()
        print(f"[*] MemoryAccessMonitor strategy: logger={args.logger_addr} pid={args.pid}")
        print(f"[*] Waiting {args.duration}s...")
        print(f"[*] Trigger: open FTA, send/receive message, scroll chat")
        sys.stdout.flush()
        time.sleep(max(1, args.duration))
    finally:
        out.write_text(json.dumps({"pid": args.pid, "events": events}, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))
        sys.stdout.flush()
        try:
            sess.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
