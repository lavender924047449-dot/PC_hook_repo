"""
诊断脚本：读取 logger(0xa3616d0) 的全部参数（args[0..4]），
找到 PID 20632 中 SQL 文本 + 结果值的位置。
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Dump full logger args to locate SQL+result in PID 20632")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--addr", default="0xa3616d0")
    parser.add_argument("--duration", type=int, default=90)
    parser.add_argument("--max-events", type=int, default=5)
    parser.add_argument("--dump-len", type=int, default=512)
    parser.add_argument("--out", default="runtime/wecom_re/logger_full_args.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    events: list[dict] = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
const TARGET = ptr("%ADDR%");
const MAX_EVENTS = %MAX%;
const DUMP_LEN = %DUMP_LEN%;
let count = 0;

function s8(p, n) { try { const t = p.readCString(); return t ? t.slice(0, n||200) : ""; } catch (e) { return ""; } }
function hd(p, n) { try { return hexdump(p, {offset:0, length:n, header:false, ansi:false}); } catch (e) { return ""; } }
function looksPtr(v) { return v >= 0x10000 && v < 0x7fff0000; }
function u32(p) { try { return p.readU32()>>>0; } catch(e) { return 0; } }

// Search for SQL bytes in a buffer
function findSql(p, len) {
  try {
    const needle = [0x73,0x65,0x6c,0x65,0x63,0x74,0x20,0x73,0x65,0x71,0x75,0x65,0x6e,0x63,0x65]; // 'select sequence'
    const raw = p.readByteArray(len);
    const bytes = new Uint8Array(raw);
    for (let i = 0; i < bytes.length - needle.length; i++) {
      let ok = true;
      for (let j = 0; j < needle.length; j++) if (bytes[i+j] !== needle[j]) { ok=false; break; }
      if (ok) return { offset: i, ptr: p.add(i).toString(), sql: s8(p.add(i), 150) };
    }
  } catch(e) {}
  return null;
}

Interceptor.attach(TARGET, {
  onEnter(args) {
    if (count >= MAX_EVENTS) return;
    const a0 = args[0];
    const path = s8(a0, 256);
    if (path.indexOf("message_lookup.db") < 0) return;
    count += 1;

    const result = {
      ts: Date.now(),
      ret: this.returnAddress.toString(),
      path: path,
    };

    // Dump args 0..4
    for (let i = 0; i < 5; i++) {
      const aptr = args[i];
      const av = aptr.toInt32() >>> 0;
      const ainfo = {
        ptr: aptr.toString(),
        u32: av,
        hex: "0x" + av.toString(16),
        s8: s8(aptr, 100),
      };
      if (looksPtr(av)) {
        ainfo.hd = hd(aptr, DUMP_LEN);
        ainfo.sql_found = findSql(aptr, DUMP_LEN);
      }
      result["a" + i] = ainfo;
    }

    // Also get stack directly
    const esp = this.context.esp;
    result.stack_hd = hd(esp, 128);
    result.regs = {
      eax: this.context.eax.toString(),
      ebx: this.context.ebx.toString(),
      ecx: this.context.ecx.toString(),
      edx: this.context.edx.toString(),
      esi: this.context.esi.toString(),
      edi: this.context.edi.toString(),
      ebp: this.context.ebp.toString(),
      esp: esp.toString(),
    };

    // EBP walk to find frame with select sequence context
    let ebp = this.context.ebp;
    const frames = [];
    for (let i = 0; i < 8; i++) {
      const ret = u32(ebp.add(4));
      const a12v = u32(ebp.add(12));
      const a28v = u32(ebp.add(28));
      frames.push({ i: i, ret: "0x" + ret.toString(16), a12_hex: "0x" + a12v.toString(16),
                    a12_u32: a12v, a28_u32: a28v });
      const nxt = u32(ebp);
      if (!looksPtr(nxt) || nxt <= (ebp.toInt32()>>>0)) break;
      ebp = ptr(nxt);
    }
    result.frames = frames;

    send(result);
  }
});
"""
        js = (js
              .replace("%ADDR%", args.addr)
              .replace("%MAX%", str(max(1, args.max_events)))
              .replace("%DUMP_LEN%", str(max(64, args.dump_len))))

        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") == "send":
                events.append(msg.get("payload", {}))
            elif msg.get("type") == "error":
                events.append({"frida_error": msg})

        script.on("message", on_message)
        script.load()
        print(f"[*] logger_full_args: hooked {args.addr} pid={args.pid}")
        print(f"[*] Waiting {args.duration}s ... 请打开图片/文件再返回聊天来触发")
        time.sleep(max(1, args.duration))
    finally:
        try:
            sess.detach()
        except Exception:
            pass

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
