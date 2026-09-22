"""
扫描 SQL 字符串的代码交叉引用，找 GetMessageSequenceAndTime 的实际调用地址
"""
import frida, sys, time, json
from pathlib import Path

SQL_VA = 0x266d75f0

js = r"""
const SQL_VA = %SQL_VA%;
const sqlPtr = ptr(SQL_VA);

// Verify SQL text
let sqlText = "";
try { sqlText = sqlPtr.readCString(); } catch(e) {}
send({type: "sql_verify", sql: sqlText.slice(0, 100)});

// Search in code ranges for PUSH imm32 = SQL_VA
const hits = [];
const ranges = Process.enumerateRanges("r-x");
for (const r of ranges) {
  if (r.size < 0x1000 || r.size > 0x3000000) continue;
  try {
    const buf = r.base.readByteArray(r.size);
    if (!buf) continue;
    const raw = new Uint8Array(buf);
    const b0 = SQL_VA & 0xFF;
    const b1 = (SQL_VA >> 8) & 0xFF;
    const b2 = (SQL_VA >> 16) & 0xFF;
    const b3 = (SQL_VA >> 24) & 0xFF;
    for (let i = 0; i < raw.length - 5; i++) {
      if (raw[i+1]===b0 && raw[i+2]===b1 && raw[i+3]===b2 && raw[i+4]===b3) {
        const op = raw[i];
        if (op === 0x68 || (op >= 0xB8 && op <= 0xBF)) {
          const addr = r.base.add(i);
          let ctx = "";
          try { ctx = hexdump(addr, {offset:0, length:20, header:false, ansi:false}); } catch(e) {}
          hits.push({addr: addr.toString(), opcode: "0x"+op.toString(16), context: ctx});
          if (hits.length >= 8) break;
        }
      }
    }
  } catch(e) {}
  if (hits.length >= 8) break;
}
send({type: "xrefs", hits: hits});
"""

js = js.replace("%SQL_VA%", str(SQL_VA))

sess = frida.attach(20632)
results = []
script = sess.create_script(js)
script.on("message", lambda m, d: results.append(m))
script.load()
time.sleep(5)
script.unload()
sess.detach()

for r in results:
    p = r.get("payload", {})
    t = p.get("type")
    if t == "sql_verify":
        print("SQL at 0x266d75f0:", p.get("sql"))
    elif t == "xrefs":
        print(f"SQL xrefs ({len(p.get('hits',[]))} found):")
        for h in p.get("hits", []):
            print(f"  addr={h['addr']} op={h['opcode']}")
            print(f"    {h['context'][:80]}")
