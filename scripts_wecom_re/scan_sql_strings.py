"""
扫描 WXWork.exe 内存，找 SQL 模板字符串 'select %1%' 以定位 GetMessageSequenceAndTime 函数。
同时找 message_table, sequence, send_time 等相关字符串。
"""
import frida, sys, time, json
from pathlib import Path

PATTERNS = [
    ("select %1%", b"select %1%"),
    ("select sequence", b"select sequence"),
    ("GetMessageSequenceAndTime", b"GetMessageSequenceAndTime"),
    ("message_table", b"message_table"),
    ("sequence, send_time", b"sequence, send_time"),
    ("message_id = ?", b"message_id = ?"),
    ("select_seq_func", b"\x68\xBE\x6B\x8B"),  # PUSH 0x8B6BBE (template addr pattern)
]

js = r"""
const PATTERNS = %PATTERNS%;
const results = {};

for (const [name, hexPat] of PATTERNS) {
  const hits = [];
  const ranges = Process.enumerateRanges('r--');
  ranges.push(...Process.enumerateRanges('r-x'));
  
  for (const r of ranges) {
    if (r.size < 0x100 || r.size > 0x4000000) continue;
    try {
      const found = Memory.scanSync(r.base, r.size, hexPat);
      for (const f of found) {
        let snippet = "";
        try { snippet = f.address.readCString().slice(0, 100); } catch(e) {}
        if (!snippet) {
          try { snippet = hexdump(f.address, {offset:0, length:20, header:false, ansi:false}); } catch(e) {}
        }
        hits.push({addr: f.address.toString(), snippet: snippet.slice(0, 100)});
        if (hits.length >= 5) break;
      }
    } catch(e) {}
    if (hits.length >= 5) break;
  }
  results[name] = hits;
}

send(results);
"""

# Build patterns as hex strings for Frida Memory.scanSync
def to_hex_pattern(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)

patterns_js = json.dumps([[name, to_hex_pattern(pat)] for name, pat in PATTERNS])
js = js.replace("%PATTERNS%", patterns_js)

sess = frida.attach(20632)
msgs = []
script = sess.create_script(js)
script.on("message", lambda m,d: msgs.append(m))
script.load()
time.sleep(8)
script.unload()
sess.detach()

for m in msgs:
    p = m.get("payload", {})
    print("=== String Scan Results ===")
    for name, hits in p.items():
        print(f"\n[{name}] ({len(hits)} hits)")
        for h in hits:
            print(f"  {h['addr']}: {h['snippet'][:80]}")
