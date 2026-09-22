"""
精确扫描：在 0x266d75f0 ±4MB 范围内查找 (sequence, send_time) 对
同时也扫 0x170ee718 区域（MessageTable 对象）
分批读取，避免超时
"""
import frida, time, json, pathlib, sys
from datetime import datetime

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\targeted_scan_results.json')

sess = frida.attach(PID)

js = r"""
var MIN_ST_HI = 0x16;
var MAX_ST_HI = 0x1C;
var MAX_SEQ = 10000000;

function scanRange(base_addr, size) {
  var results = [];
  try {
    var buf = ptr(base_addr).readByteArray(size);
    if (!buf) return results;
    var arr = new Uint32Array(buf.slice(0));
    for (var i = 0; i < arr.length - 4; i++) {
      var seq_lo = arr[i];
      var seq_hi = arr[i+1];
      var st_lo  = arr[i+2];
      var st_hi  = arr[i+3];
      if (seq_hi !== 0) continue;
      if (seq_lo > MAX_SEQ || seq_lo === 0) continue;
      if (st_hi < MIN_ST_HI || st_hi > MAX_ST_HI) continue;
      var addr = base_addr + i * 4;
      var st_ms = st_hi * 4294967296 + st_lo;
      var st_s = Math.floor(st_ms / 1000);
      if (st_s < 1577836800 || st_s > 1893456000) continue;
      results.push({addr: '0x'+addr.toString(16), seq: seq_lo, st_ms: st_ms, st_s: st_s});
      if (results.length >= 100) break;
    }
  } catch(e) {}
  return results;
}

// Scan zone 1: around 0x266d75f0 ±4MB (in 512K chunks)
var zone1_start = 0x262d75f0;
var zone1_end   = 0x26ad75f0;
var chunk = 512*1024;
var all = [];

for (var addr = zone1_start; addr < zone1_end && all.length < 200; addr += chunk) {
  var sz = Math.min(chunk, zone1_end - addr);
  var hits = scanRange(addr, sz);
  for (var i = 0; i < hits.length; i++) all.push(hits[i]);
}

// Scan zone 2: around 0x170ee718 (MessageTable object, ±1MB)
var zone2_start = 0x16FEE718;
var zone2_end   = 0x171EE718;
for (var addr = zone2_start; addr < zone2_end && all.length < 300; addr += chunk) {
  var sz = Math.min(chunk, zone2_end - addr);
  var hits = scanRange(addr, sz);
  for (var i = 0; i < hits.length; i++) all.push(hits[i]);
}

// Scan zone 3: around 0x2ba6b550 (another object from trace, ±1MB)
var zone3_start = 0x2B96B550;
var zone3_end   = 0x2BB6B550;
for (var addr = zone3_start; addr < zone3_end && all.length < 400; addr += chunk) {
  var sz = Math.min(chunk, zone3_end - addr);
  var hits = scanRange(addr, sz);
  for (var i = 0; i < hits.length; i++) all.push(hits[i]);
}

send({count: all.length, results: all.slice(0,100)});
"""

print('Starting targeted scan (3 zones)...')
sys.stdout.flush()

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))

done = [False]
def on_msg(m,d):
    msgs.append(m)
    done[0] = True
script.on('message', on_msg)

script.load()

# Wait up to 20 seconds
for _ in range(20):
    if done[0]:
        break
    time.sleep(1)

script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print(f'Found {p.get("count")} candidate pairs:')
    results = p.get('results', [])
    for r in results[:30]:
        dt = datetime.utcfromtimestamp(r.get('st_s', 0))
        print(f'  addr={r["addr"]} seq={r["seq"]} send_time={r["st_s"]} ({dt.strftime("%Y-%m-%d %H:%M:%S")} UTC)')
    
    OUT.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'Saved to {OUT}')
