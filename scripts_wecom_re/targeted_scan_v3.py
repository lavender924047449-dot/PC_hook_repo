"""
精确小范围扫描：3 个目标区域各 ±1MB
"""
import frida, time, json, pathlib
from datetime import datetime

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\targeted_scan_v3.json')

MIN_ST_HI = 0x18C  # 2024+
MAX_ST_HI = 0x1A5  # 2026+

sess = frida.attach(PID)
js = """
var MIN_ST_HI = %d;
var MAX_ST_HI = %d;

function scanChunk(base_addr, size) {
  var results = [];
  try {
    var buf = ptr(base_addr).readByteArray(size);
    if (!buf) return results;
    var arr = new Uint32Array(buf.slice(0));
    for (var i = 0; i < arr.length - 4; i++) {
      var seq_lo = arr[i], seq_hi = arr[i+1], st_lo = arr[i+2], st_hi = arr[i+3];
      if (seq_hi !== 0) continue;
      if (seq_lo === 0 || seq_lo > 10000000) continue;
      if (st_hi < MIN_ST_HI || st_hi > MAX_ST_HI) continue;
      var addr = base_addr + i*4;
      var st_ms = st_hi * 4294967296 + st_lo;
      var st_s = Math.floor(st_ms / 1000);
      if (st_s < 1577836800 || st_s > 1893456000) continue;
      results.push({a:'0x'+addr.toString(16), sq:seq_lo, st:st_s});
    }
  } catch(e) {}
  return results;
}

var chunk = 1024*1024;
var zones = [
  [0x265D75F0 - 1024*1024, 0x265D75F0 + 1024*1024],  // SQL buffer area
  [0x170EE718 - 512*1024,  0x170EE718 + 512*1024],    // MessageTable object area
  [0x2BA6B550 - 512*1024,  0x2BA6B550 + 512*1024],    // cache object area
];

var all = [];
for (var zi = 0; zi < zones.length; zi++) {
  var zstart = zones[zi][0], zend = zones[zi][1];
  for (var addr = zstart; addr < zend; addr += chunk) {
    var sz = Math.min(chunk, zend - addr);
    var hits = scanChunk(addr, sz);
    for (var k = 0; k < hits.length; k++) all.push(hits[k]);
    if (all.length >= 300) break;
  }
}

send({count: all.length, results: all.slice(0,100)});
""" % (MIN_ST_HI, MAX_ST_HI)

msgs = []
script = sess.create_script(js)
done = [False]
def on_msg(m,d):
    msgs.append(m)
    done[0] = True
script.on('message', on_msg)

script.load()
for _ in range(20):
    if done[0]:
        break
    time.sleep(1)

script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print(f'Found {p.get("count")} pairs:')
    for r in p.get('results', [])[:30]:
        dt = datetime.utcfromtimestamp(r.get('st', 0))
        print(f'  addr={r["a"]} seq={r["sq"]} ts={r["st"]} ({dt.strftime("%Y-%m-%d %H:%M")} UTC)')
    OUT.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'Saved to {OUT}')
