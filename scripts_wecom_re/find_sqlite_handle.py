"""
直接在进程内执行 SQL 查询策略：
1. 通过内存扫描找到 message_lookup.db 的 sqlite3* 句柄
2. 找到 sqlite3_exec / sqlite3_prepare_v2 函数地址（签名扫描）
3. 通过 NativeFunction 直接查询 message_table

依据：
- 0x660e0ba0 在多个事件中稳定出现，可能是 sqlite3* 或包装对象
- 从日志事件的 a0 buffer 找到 DB open 句柄
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import frida


def main() -> None:
    parser = argparse.ArgumentParser(description="Direct sqlite3 execution in WXWork process")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--logger-addr", default="0xa3616d0")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--out", default="runtime/wecom_re/direct_sql_result.json")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    results = []

    sess = frida.attach(args.pid)
    try:
        js = r"""
// Strategy: find sqlite3* handle from logger events, then try to call sqlite3_exec

const LOGGER = ptr("%LOGGER%");

function u32(p) { try { return p.readU32()>>>0; } catch(e) { return 0; } }
function s8(p, n) { try { const t=p.readCString(); return t?t.slice(0,n||200):""; } catch(e){ return ""; } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return ""; } }
function looksPtr(v) { return v>=0x10000 && v<0x7fff0000; }

// Candidate sqlite3* values seen in previous analysis
const candidates = [
  0x660e0ba0,  // consistent in bind_deep frame[5].a24
  0x660e0a28,  // a24/a20 in postcall
  0x660e0408,  // frame[1] in bind_deep
  0x660e0460,
];

// Also try to find sqlite3_exec by scanning for known SQL string
let sql_text_va = null;
try {
  const needle = "select sequence, send_time from message_table where message_id = ? limit 1;";
  const needleBytes = [];
  for (let i = 0; i < needle.length; i++) needleBytes.push(needle.charCodeAt(i));
  const needleHex = needleBytes.map(b => b.toString(16).padStart(2,'0')).join(' ');
  
  const ranges = Process.enumerateRanges('r--');
  for (const r of ranges) {
    if (r.size < 0x1000 || r.size > 0x8000000) continue;
    let found = [];
    try { found = Memory.scanSync(r.base, r.size, needleHex); } catch(e) {}
    if (found.length > 0) {
      sql_text_va = found[0].address.toString();
      break;
    }
  }
} catch(e) {}

// Try to find sqlite3 internal structures
// sqlite3* starts with:
//   offset 0: sqlite3_vfs* pVfs
//   offset 4: Db* aDb (pointer to array of Db structs)
// A valid sqlite3* handle will have reasonable pointers at these offsets

function validateSqlite3Handle(p) {
  try {
    const pVfs = u32(p);
    const pDb = u32(p.add(4));
    // pVfs should be a valid pointer into WXWork module range
    // pDb should be a valid pointer
    if (!looksPtr(pVfs) || !looksPtr(pDb)) return false;
    // Check pVfs structure - first field is zName string pointer
    const zName = u32(ptr(pVfs));
    if (!looksPtr(zName)) return false;
    const vfsName = s8(ptr(zName), 20);
    if (!vfsName || vfsName.length === 0) return false;
    return true;
  } catch(e) { return false; }
}

const validated = [];
for (const cand of candidates) {
  const p = ptr(cand);
  const valid = validateSqlite3Handle(p);
  const hd4 = hd(p, 32);
  validated.push({addr: "0x"+cand.toString(16), valid: valid, hd: hd4});
}

// Also hook logger to capture db handles dynamically
let capturedHandles = [];
let loggerHits = 0;

Interceptor.attach(LOGGER, {
  onEnter(args) {
    if (loggerHits > 20) return;
    const path = s8(args[0], 256);
    if (path.indexOf("message_lookup.db") < 0) return;
    loggerHits++;
    
    // Walk frames to find potential DB handle
    let ebp = this.context.ebp;
    for (let i = 0; i < 7; i++) {
      // Check a24 [ebp+24] - potential DB handle
      const a24 = u32(ebp.add(24));
      if (looksPtr(a24) && a24 > 0x60000000 && a24 < 0x70000000) {
        if (!capturedHandles.includes(a24)) {
          capturedHandles.push(a24);
        }
      }
      const nxt = u32(ebp);
      if (!looksPtr(nxt) || nxt <= (ebp.toInt32()>>>0)) break;
      ebp = ptr(nxt);
    }
  }
});

setTimeout(function() {
  // Validate captured handles too
  const dynamicValidated = capturedHandles.map(h => {
    const p = ptr(h);
    return {addr: "0x"+h.toString(16), valid: validateSqlite3Handle(p), hd: hd(p, 48)};
  });
  
  send({
    sql_text_found_at: sql_text_va,
    static_candidates: validated,
    dynamic_handles: dynamicValidated,
    logger_hits: loggerHits,
  });
}, %DURATION_MS%);
"""
        js = (js
              .replace("%LOGGER%", args.logger_addr)
              .replace("%DURATION_MS%", str((args.duration - 2) * 1000)))

        script = sess.create_script(js)

        def on_message(msg, data):
            if msg.get("type") == "send":
                results.append(msg.get("payload", {}))
            elif msg.get("type") == "error":
                results.append({"frida_error": msg})

        script.on("message", on_message)
        script.load()
        print(f"[*] Attached pid={args.pid} duration={args.duration}s")
        print(f"[*] Looking for sqlite3 handles... please trigger FTA activity")
        sys.stdout.flush()
        time.sleep(max(1, args.duration))
    finally:
        out.write_text(json.dumps({"pid": args.pid, "results": results}, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        print(json.dumps({"out": str(out), "results_count": len(results)}, ensure_ascii=False))
        sys.stdout.flush()
        try:
            sess.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
