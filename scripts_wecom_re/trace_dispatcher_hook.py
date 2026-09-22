"""
钩住 GetMessageSequenceAndTime 的 dispatcher 函数 (0x8b6b4c2)。
策略：
  onEnter: 检查 [ebp+0x14]==2 (case2=GetMessageSequenceAndTime), 保存 [ebp+0xC] (a12=struct)
  onLeave: 读取 struct 前 128 字节，sequence/send_time 应已填入
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Hook GetMessageSequenceAndTime dispatcher")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--dispatcher", default="0x8b6b4c2",
                        help="Dispatcher function addr (case2=GetMessageSequenceAndTime)")
    parser.add_argument("--duration", type=int, default=90)
    parser.add_argument("--max-events", type=int, default=8)
    parser.add_argument("--out", default="runtime/wecom_re/dispatcher_hook.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const DISPATCHER = ptr("%DISPATCHER%");
const MAX_EVENTS = %MAX%;
let count = 0;

// tid -> {a12ptr, message_id, case_val, ts}
const pending = new Map();

function u32(p) { try { return p.readU32()>>>0; } catch(e){ return 0; } }
function s8(p, n) { try { const t=p.readCString(); return t?t.slice(0,n||100):""; } catch(e){ return ""; } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return ""; } }
function looksPtr(v) { return v>=0x10000 && v<0x7fff0000; }
function u64at(p) {
  try {
    const lo=p.readU32()>>>0, hi=p.add(4).readU32()>>>0;
    return {lo:lo,hi:hi,
            hex:"0x"+hi.toString(16).padStart(8,"0")+lo.toString(16).padStart(8,"0"),
            dec:((BigInt(hi)<<32n)+BigInt(lo)).toString()};
  } catch(e) { return null; }
}
function dumpStruct(base, nSlots) {
  const rows = [];
  for (let i = 0; i < nSlots; i++) {
    const off = i*4;
    const v = u32(base.add(off));
    const row = {off:off, hex:"0x"+v.toString(16), u32:v};
    row.u64_here = u64at(base.add(off));
    if (looksPtr(v)) {
      const p = ptr(v);
      row.s8 = s8(p, 60);
      row.u64_at = u64at(p);
    }
    rows.push(row);
  }
  return rows;
}

Interceptor.attach(DISPATCHER, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const ebp = this.context.ebp;
    
    // Read the case selector at [ebp+0x14]
    const caseVal = u32(ebp.add(0x14));
    
    // Also read a12 = [ebp+0xC] (struct pointer with message_id)
    const a12 = u32(ebp.add(0xC));
    const a8  = u32(ebp.add(0x8));
    const a16 = u32(ebp.add(0x10));
    
    // Only care about case 2 (GetMessageSequenceAndTime)
    if (caseVal !== 2) return;
    
    const tid = this.threadId;
    const msgId = looksPtr(a12) ? u32(ptr(a12)) : 0;
    
    pending.set(tid, {
      a12: a12,
      a8: a8,
      a16: a16,
      case_val: caseVal,
      msg_id_pre: msgId,
      struct_pre: looksPtr(a12) ? dumpStruct(ptr(a12), 16) : [],
      hd_pre: looksPtr(a12) ? hd(ptr(a12), 128) : "",
      regs_entry: {
        eax: this.context.eax.toString(),
        ebx: this.context.ebx.toString(),
        ecx: this.context.ecx.toString(),
        esi: this.context.esi.toString(),
      },
      ts: Date.now(),
    });
  },
  
  onLeave(retval) {
    const tid = this.threadId;
    const info = pending.get(tid);
    if (!info) return;
    pending.delete(tid);
    
    if (count >= MAX_EVENTS) return;
    count += 1;
    
    const a12 = info.a12;
    const structPost = looksPtr(a12) ? dumpStruct(ptr(a12), 16) : [];
    const hdPost = looksPtr(a12) ? hd(ptr(a12), 128) : "";
    
    send({
      ts: info.ts,
      ts_leave: Date.now(),
      tid: tid,
      case_val: info.case_val,
      a8: "0x" + (info.a8>>>0).toString(16),
      a12: "0x" + (a12>>>0).toString(16),
      a16: "0x" + (info.a16>>>0).toString(16),
      msg_id_pre: info.msg_id_pre,
      struct_pre: info.struct_pre,
      hd_pre: info.hd_pre,
      struct_post: structPost,
      hd_post: hdPost,
      retval: retval.toString(),
      regs_entry: info.regs_entry,
    });
  }
});
"""
        js = (js
              .replace("%DISPATCHER%", args.dispatcher)
              .replace("%MAX%", str(max(1, args.max_events))))

        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") == "send":
                events.append(msg.get("payload", {}))
            elif msg.get("type") == "error":
                events.append({"frida_error": msg})

        script.on("message", on_message)
        script.load()
        print(f"[*] Hooked dispatcher={args.dispatcher} pid={args.pid}")
        print(f"[*] Waiting {args.duration}s for GetMessageSequenceAndTime (case 2) calls...")
        print(f"[*] Trigger: open FTA, send message, scroll chat, click on messages")
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
