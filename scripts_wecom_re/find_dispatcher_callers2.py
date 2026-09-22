"""
精确扫描：在 dispatcher ±8MB 范围内找 push 2 + call dispatcher
"""
import frida, time, json

sess = frida.attach(20632)
js = r"""
var DISP = 0x08b6b4c2;
// Scan ±8MB around dispatcher  
var scan_start = DISP - 8*1024*1024;
if (scan_start < 0x800000) scan_start = 0x800000;
var scan_end = DISP + 8*1024*1024;
if (scan_end > 0x10A0A000) scan_end = 0x10A0A000;

var results = [];

function scanChunk(base_addr, size) {
  try {
    var p = ptr(base_addr);
    var buf = p.readByteArray(size);
    if (!buf) return;
    var arr = new Uint8Array(buf);
    for (var j = 0; j < arr.length - 5; j++) {
      if (arr[j] !== 0xe8) continue;
      var rel32 = arr[j+1] | (arr[j+2]<<8) | (arr[j+3]<<16) | (arr[j+4]<<24);
      var caller = base_addr + j;
      var next_ip = caller + 5;
      var target = (next_ip + rel32) >>> 0;
      if (target === DISP) {
        // Check 30 bytes before for 'push 2' = 6a 02
        var has_push2 = false;
        for (var k = Math.max(0, j-30); k < j; k++) {
          if (arr[k] === 0x6a && arr[k+1] === 0x02) { has_push2 = true; break; }
          if (arr[k] === 0x68 && arr[k+1] === 0x02 && arr[k+2] === 0x00 && arr[k+3] === 0x00 && arr[k+4] === 0x00) { has_push2 = true; break; }
        }
        // Dump 48 bytes before caller
        var pre = [];
        for (var k = Math.max(0, j-48); k <= j+4; k++) {
          pre.push(arr[k].toString(16).padStart(2,'0'));
        }
        results.push({
          caller: '0x'+caller.toString(16),
          has_push2: has_push2,
          bytes: pre.join(' ')
        });
        if (results.length >= 30) return;
      }
    }
  } catch(e) {}
}

// Scan in 512KB chunks to avoid timeout
var CHUNK = 512*1024;
for (var addr = scan_start; addr < scan_end && results.length < 30; addr += CHUNK) {
  var sz = Math.min(CHUNK, scan_end - addr);
  scanChunk(addr, sz);
}

send({ count: results.length, results: results });
"""

msgs = []
script = sess.create_script(js)
# Allow 25s for scan
import threading
done = threading.Event()
def on_msg(m,d):
    msgs.append(m)
    done.set()
script.on('message', on_msg)
script.load()
done.wait(timeout=25)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print(f"Found {p.get('count')} callers of dispatcher:")
    for r in p.get('results', []):
        mark = " <<< CASE 2" if r['has_push2'] else ""
        print(f"\n  Caller: {r['caller']}{mark}")
        print(f"  Bytes: {r['bytes']}")
