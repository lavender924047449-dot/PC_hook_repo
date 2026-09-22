from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Dump stable ebx object + frame pointers when lookup SQL fires.")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa6316d0")
    parser.add_argument("--duration", type=int, default=75)
    parser.add_argument("--max-events", type=int, default=6)
    parser.add_argument("--out", default="runtime/wecom_re/lookup_object_dump.json")
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
function s8(p){ try { const t=p.readCString(); return t?t.slice(0,100):""; } catch(e){ return ""; } }
function hd(p,n){ try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return ""; } }
function looks(v){ return v>=0x10000 && v<0x7fff0000; }
function u64(p){
  try {
    const lo=p.readU32()>>>0, hi=p.add(4).readU32()>>>0;
    return {hex:"0x"+hi.toString(16).padStart(8,"0")+lo.toString(16).padStart(8,"0"),
            dec:((BigInt(hi)<<32n)+BigInt(lo)).toString(), lo:lo, hi:hi};
  } catch(e){ return null; }
}
function dumpObj(base, n){
  const rows=[];
  for (let i=0;i<n;i++){
    const off=i*4;
    const v=u32(base.add(off));
    const rec={off:off, hex:"0x"+v.toString(16), u32:v, s8:"", u64:null};
    if (looks(v)) { rec.s8=s8(ptr(v)); rec.u64=u64(ptr(v)); rec.hd=hd(ptr(v), 24); }
    rec.u64_here=u64(base.add(off));
    rows.push(rec);
  }
  return rows;
}
Interceptor.attach(target, {
  onEnter(args){
    if (count>=MAX_EVENTS) return;
    const path=s8(args[0]);
    if (path.indexOf("message_lookup.db")<0) return;
    let sql="";
    try {
      const bytes=new Uint8Array(args[0].readByteArray(384));
      const n=[0x73,0x65,0x6c,0x65,0x63,0x74,0x20,0x73,0x65,0x71];
      for (let i=0;i<bytes.length-n.length;i++){
        let ok=true;
        for (let j=0;j<n.length;j++) if (bytes[i+j]!==n[j]) {ok=false; break;}
        if (ok) { sql=s8(args[0].add(i)); break; }
      }
    } catch(e){}
    if (sql.indexOf("select sequence")<0) return;
    count+=1;
    const ebx=this.context.ebx;
    const ebp=this.context.ebp;
    // Walk to frame 5 if possible (ret 0xe6114b historically)
    let f5=null, cur=ebp;
    for (let i=0;i<8;i++){
      const ret=u32(cur.add(4));
      if (ret===0xe6114b || ret===0xe60b39) {
        f5={i:i, ret:"0x"+ret.toString(16), a8:u32(cur.add(8)), a12:u32(cur.add(12)), a16:u32(cur.add(16)), a20:u32(cur.add(20))};
        break;
      }
      const nxt=u32(cur);
      if (!looks(nxt) || nxt<=(cur.toInt32()>>>0)) break;
      cur=ptr(nxt);
    }
    const extra={};
    if (f5 && looks(f5.a12)) extra.frame_a12 = {ptr:"0x"+f5.a12.toString(16), hd:hd(ptr(f5.a12), 96), fields:dumpObj(ptr(f5.a12), 16)};
    if (f5 && looks(f5.a8)) extra.frame_a8 = {ptr:"0x"+f5.a8.toString(16), hd:hd(ptr(f5.a8), 64), fields:dumpObj(ptr(f5.a8), 12)};
    send({
      ts:Date.now(),
      sql:sql,
      ebx:ebx.toString(),
      ebx_hd:hd(ebx, 128),
      ebx_fields:dumpObj(ebx, 24),
      frame:f5,
      extra:extra
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

    payload = {"pid": args.pid, "event_count": len(events), "events": events}
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "event_count": len(events)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
