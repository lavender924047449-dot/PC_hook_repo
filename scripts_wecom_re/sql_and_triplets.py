"""
重新扫描：找 'select sequence' SQL 字符串的当前位置
然后在其 ±64KB 处找 (seq, send_time) 对
"""
import frida, time, json, pathlib
from datetime import datetime

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\sql_and_triplets.json')

MIN_ST_HI = 0x18C
MAX_ST_HI = 0x1A5

sess = frida.attach(PID)
js = """
var MIN_ST_HI = %d;
var MAX_ST_HI = %d;

// Step 1: Find SQL strings using Memory.scanSync
var sql_pattern1 = '73 65 6c 65 63 74 20 73 65 71 75 65 6e 63 65'; // 'select sequence'
var sql_pattern2 = '73 65 71 75 65 6e 63 65 2c 20 73 65 6e 64 5f 74 69 6d 65'; // 'sequence, send_time'

var sql_hits = [];
var ranges = Process.enumerateRanges({protection:'r--', coalesce:true})
  .concat(Process.enumerateRanges({protection:'rw-', coalesce:true}));

for (var ri = 0; ri < ranges.length; ri++) {
  var r = ranges[ri];
  var base = r.base.toUInt32();
  if (base < 0x10000) continue;
  if (r.size > 64*1024*1024) continue; // skip very large
  try {
    var hits = Memory.scanSync(r.base, r.size, sql_pattern2);
    for (var i = 0; i < hits.length; i++) {
      sql_hits.push({addr: '0x'+hits[i].address.toUInt32().toString(16), 
                     ctx: hits[i].address.readUtf8String(80)});
    }
    if (sql_hits.length >= 20) break;
  } catch(e) {}
}

// Step 2: Scan around each SQL hit for (seq, send_time) pairs
function scanChunk(base_addr, size) {
  var results = [];
  try {
    var buf = ptr(base_addr).readByteArray(size);
    if (!buf) return results;
    var arr = new Uint32Array(buf.slice(0));
    for (var i = 0; i < arr.length - 4; i++) {
      var sq_lo = arr[i], sq_hi = arr[i+1], st_lo = arr[i+2], st_hi = arr[i+3];
      if (sq_hi !== 0) continue;
      if (sq_lo === 0 || sq_lo > 10000000) continue;
      if (st_hi < MIN_ST_HI || st_hi > MAX_ST_HI) continue;
      var st_ms = st_hi * 4294967296 + st_lo;
      var st_s = Math.floor(st_ms / 1000);
      if (st_s < 1577836800 || st_s > 1893456000) continue;
      results.push({a:'0x'+(base_addr+i*4).toString(16), sq:sq_lo, st:st_s});
    }
  } catch(e) {}
  return results;
}

var triplets = [];
for (var si = 0; si < sql_hits.length; si++) {
  var sql_addr = parseInt(sql_hits[si].addr, 16);
  var scan_start = Math.max(0x10000, sql_addr - 128*1024);
  var scan_end   = sql_addr + 128*1024;
  var chunk = 64*1024;
  for (var addr = scan_start; addr < scan_end; addr += chunk) {
    var sz = Math.min(chunk, scan_end - addr);
    var hits = scanChunk(addr, sz);
    for (var k = 0; k < hits.length; k++) triplets.push(hits[k]);
  }
}

send({sql_hits: sql_hits, triplets: triplets.slice(0,50)});
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
    print('SQL hits:')
    for h in p.get('sql_hits', []):
        print(f'  {h["addr"]}: {repr(h["ctx"][:60])}')
    print(f'\nTriplets ({len(p.get("triplets",[]))} found):')
    for t in p.get('triplets', [])[:20]:
        dt = datetime.utcfromtimestamp(t.get('st', 0))
        print(f'  addr={t["a"]} seq={t["sq"]} ts={t["st"]} ({dt.strftime("%Y-%m-%d %H:%M")} UTC)')
    OUT.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'Saved to {OUT}')
