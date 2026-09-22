from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hook instruction after vtable call at 0xE6114B; dump args (possible sequence/send_time out-params)."
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xe6114b")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--max-events", type=int, default=10)
    parser.add_argument("--out", default="runtime/wecom_re/vtable_postcall_dump.json")
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
function u32(p){ try { return p.readU32()>>>0; } catch(e){ return 0; } }
function s8(p){ try { const t=p.readCString(); return t?t.slice(0,80):""; } catch(e){ return ""; } }
function hd(p,n){ try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return ""; } }
function looks(v){ return v>=0x10000 && v<0x7fff0000; }
function u64(p){
  try {
    const lo=p.readU32()>>>0, hi=p.add(4).readU32()>>>0;
    return {hex:"0x"+hi.toString(16).padStart(8,"0")+lo.toString(16).padStart(8,"0"),
            dec:((BigInt(hi)<<32n)+BigInt(lo)).toString(), lo:lo, hi:hi};
  } catch(e){ return null; }
}
function dumpPtr(v){
  const rec={hex:"0x"+(v>>>0).toString(16), u32:v>>>0, s8:"", u64:null, hd:""};
  if (!looks(v)) return rec;
  rec.s8=s8(ptr(v));
  rec.u64=u64(ptr(v));
  rec.hd=hd(ptr(v), 48);
  return rec;
}
Interceptor.attach(target, {
  onEnter(args){
    if (count>=MAX_EVENTS) return;
    const esp=this.context.esp;
    const a0=u32(esp), a1=u32(esp.add(4)), a2=u32(esp.add(8)), a3=u32(esp.add(12));
    count+=1;
    send({
      ts:Date.now(),
      eax:this.context.eax.toString(),
      ebx:this.context.ebx.toString(),
      esi:this.context.esi.toString(),
      edi:this.context.edi.toString(),
      a0:dumpPtr(a0),
      a1:dumpPtr(a1),
      a2:dumpPtr(a2),
      a3:dumpPtr(a3),
      ebp_e0:dumpPtr(u32(this.context.ebp.sub(0x20))),
      ebp_c:dumpPtr(u32(this.context.ebp.add(0xC)))
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

    payload = {"pid": args.pid, "addr": args.addr, "event_count": len(events), "events": events}
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
