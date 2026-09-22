"""
内存扫描法：扫描进程内存中的 (sequence, send_time) 数据对
- send_time 是 Unix 毫秒时间戳（2026年 = 约 1788xxxxxxx000）
- sequence 是小整数（0~100000）
两者作为 int64 存放在相邻的 8+8 字节里
"""
import frida, time, json, pathlib, sys

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\mem_scan_triplets.json')

sess = frida.attach(PID)
js = r"""
// Scan heap/data ranges for (sequence u64, send_time i64) pairs
// send_time range: 2020-01-01=1577836800s to 2030-01-01=1893456000s
// In milliseconds: 1577836800000 to 1893456000000
// In hex: 0x16F3A9CF00 to 0x1B90C4DC00
// => hi dword: 0x16 to 0x1B, lo dword: varies

// sequence: 0 to 10,000,000 (fits in u32, hi dword = 0)

// Pattern: 
// [seq_lo: 4 bytes][seq_hi: 4 bytes=0][st_lo: 4 bytes][st_hi: 4 bytes, 0x16~0x1B]
// => filter on st_hi in [0x16, 0x1B]

var results = [];
var ranges = Process.enumerateRanges({protection:'r--', coalesce:true})
  .concat(Process.enumerateRanges({protection:'rw-', coalesce:true}));

var MIN_ST_HI = 0x16;
var MAX_ST_HI = 0x1C;
var MAX_SEQ = 10000000;
var MAX_RESULTS = 200;

for (var ri = 0; ri < ranges.length && results.length < MAX_RESULTS; ri++) {
  var r = ranges[ri];
  var base = r.base.toUInt32();
  if (base < 0x10000) continue;
  if (base > 0x7FFF0000) continue;
  
  var sz = r.size;
  if (sz > 32*1024*1024) continue; // skip huge ranges
  
  try {
    var buf = r.base.readByteArray(sz);
    if (!buf) continue;
    var arr = new Uint32Array(buf.slice(0)); // read as uint32 array
    
    // Scan for [seq_lo][0][st_lo][st_hi in range] pattern
    for (var i = 0; i < arr.length - 4; i++) {
      var seq_lo = arr[i];
      var seq_hi = arr[i+1];
      var st_lo  = arr[i+2];
      var st_hi  = arr[i+3];
      
      if (seq_hi !== 0) continue;
      if (seq_lo > MAX_SEQ || seq_lo === 0) continue;
      if (st_hi < MIN_ST_HI || st_hi > MAX_ST_HI) continue;
      
      var addr = base + i * 4;
      
      // Convert: sequence = seq_lo (uint64 lo)
      // send_time as ms: st_hi * 2^32 + st_lo
      var st_ms = st_hi * 4294967296 + st_lo;
      var st_s = Math.floor(st_ms / 1000);
      
      // Sanity check: st_s should be in year 2020-2030
      if (st_s < 1577836800 || st_s > 1893456000) continue;
      
      results.push({
        addr: '0x' + addr.toString(16),
        sequence: seq_lo,
        send_time_ms: st_ms,
        send_time_s: st_s,
        range_base: '0x' + base.toString(16)
      });
      
      if (results.length >= MAX_RESULTS) break;
    }
  } catch(e) {}
}

send({count: results.length, results: results});
"""

print('Scanning memory for sequence+send_time pairs...')
sys.stdout.flush()

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
# Wait for scan to complete
time.sleep(15)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print(f'Found {p.get("count")} candidate pairs:')
    results = p.get('results', [])
    for r in results[:30]:
        from datetime import datetime
        dt = datetime.utcfromtimestamp(r['send_time_s'])
        print(f'  addr={r["addr"]} seq={r["sequence"]} send_time_s={r["send_time_s"]} ({dt}) range={r["range_base"]}')
    
    OUT.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'\nSaved to {OUT}')
