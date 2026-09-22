"""
修复版内存扫描：正确计算 2024-2026 年毫秒时间戳 hi dword 范围
2024-01-01 ms = ~0x18C_9B080000
2026-09-09 ms = ~0x1A0_5A335E40
hi dword range: [0x18C, 0x1A5]
"""
import frida, time, json, pathlib, sys
from datetime import datetime

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\targeted_scan_v2.json')

# 验证计算
import time as t_mod
ts_2024 = 1704067200000  # 2024-01-01
ts_2026 = 1788957671059  # from trace (confirmed real ts)
for ts, label in [(ts_2024, "2024-01-01"), (ts_2026, "trace ts 2026")]:
    hi = ts >> 32
    lo = ts & 0xFFFFFFFF
    print(f'{label}: ts={ts} hi=0x{hi:08x}({hi}) lo=0x{lo:08x}')

print()

sess = frida.attach(PID)
js = r"""
// Correct range for 2024-2026 millisecond timestamps:
// 2024-01-01: hi = 0x18C (396)
// 2026-12-31: hi = 0x1A5 (421)
var MIN_ST_HI = 0x18C;  // 396
var MAX_ST_HI = 0x1A5;  // 421
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
    }
  } catch(e) {}
  return results;
}

var chunk = 2*1024*1024;  // 2MB chunks
var all = [];

// Multi-zone scan
var zones = [
  // Zone 1: around previously found SQL buffer
  [0x262d75f0, 0x26cd75f0],
  // Zone 2: broad heap scan 0x10000000-0x30000000
  [0x10000000, 0x14000000],
  [0x14000000, 0x18000000],
  [0x18000000, 0x1C000000],
  [0x1C000000, 0x20000000],
  [0x20000000, 0x24000000],
  [0x24000000, 0x28000000],
  [0x28000000, 0x2C000000],
  [0x2C000000, 0x30000000],
];

for (var zi = 0; zi < zones.length && all.length < 500; zi++) {
  var zstart = zones[zi][0], zend = zones[zi][1];
  for (var addr = zstart; addr < zend && all.length < 500; addr += chunk) {
    var sz = Math.min(chunk, zend - addr);
    var hits = scanRange(addr, sz);
    for (var i = 0; i < hits.length; i++) all.push(hits[i]);
  }
}

send({count: all.length, results: all.slice(0, 100)});
"""

print('Starting corrected scan (zones 0x10M-0x30M)...')
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
for _ in range(20):
    if done[0]:
        break
    time.sleep(1)

script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print(f'\nFound {p.get("count")} candidate pairs:')
    results = p.get('results', [])
    for r in results[:30]:
        dt = datetime.utcfromtimestamp(r.get('st_s', 0))
        print(f'  addr={r["addr"]} seq={r["seq"]} send_time={r["st_s"]} ({dt.strftime("%Y-%m-%d %H:%M:%S")} UTC)')
    
    OUT.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'Saved to {OUT}')
