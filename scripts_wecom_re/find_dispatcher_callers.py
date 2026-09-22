"""
扫描调用 dispatcher(0x8b6b4c2) 的调用点，找 case=2 调用处
"""
import frida, time, json, pathlib

sess = frida.attach(20632)
js = r"""
var DISPATCHER = 0x08b6b4c2;

// Scan code pages for CALL instructions targeting the dispatcher
// Relative CALL: e8 <rel32>, target = next_ip + rel32(signed)
// rel32 = DISPATCHER - (caller_addr + 5)

var results = [];
var ranges = Process.enumerateRanges('r-x');
for (var i = 0; i < ranges.length; i++) {
  var r = ranges[i];
  if (r.base.toUInt32() < 0x00400000) continue; // skip low ranges
  if (r.base.toUInt32() > 0x20000000) continue; // skip very high
  try {
    var buf = r.base.readByteArray(r.size);
    if (!buf) continue;
    var arr = new Uint8Array(buf);
    for (var j = 0; j < arr.length - 5; j++) {
      if (arr[j] !== 0xe8) continue;
      var rel32 = arr[j+1] | (arr[j+2]<<8) | (arr[j+3]<<16) | (arr[j+4]<<24);
      var caller = r.base.toUInt32() + j;
      var next_ip = caller + 5;
      var target = (next_ip + rel32) >>> 0;
      if (target === DISPATCHER) {
        // Found a CALL to dispatcher!
        // Read 60 bytes before caller to see the setup
        var pre_addr = caller >= 60 ? caller - 60 : 0;
        var pre_dump = '';
        try { pre_dump = hexdump(ptr(pre_addr), {offset:0,length:80,header:false,ansi:false}); } catch(e) {}
        // Also read the 10 bytes immediately before to find the "push 2" (or whatever case)
        var setup = [];
        for (var k = Math.max(0, j-20); k < j; k++) {
          setup.push(arr[k].toString(16).padStart(2,'0'));
        }
        results.push({
          caller: '0x'+caller.toString(16),
          setup_hex: setup.join(' '),
          pre_dump: pre_dump.slice(0,300)
        });
        if (results.length >= 20) break;
      }
    }
  } catch(e) {}
  if (results.length >= 20) break;
}

send({ count: results.length, callers: results });
"""

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
time.sleep(10)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print(f"Found {p.get('count')} callers of dispatcher:")
    for c in p.get('callers', []):
        print(f"\n  Caller: {c['caller']}")
        print(f"  Setup (20 bytes before): {c['setup_hex']}")
        # Look for 'push 2' = 6a 02 or 'push 00000002' = 68 02 00 00 00
        setup = c['setup_hex']
        if '6a 02' in setup or '68 02 00 00 00' in setup:
            print(f"  >>> CASE 2 FOUND! <<<")
        print(f"  Context bytes before:")
        for line in c['pre_dump'].split('\n')[:8]:
            print(f"    {line}")

out = pathlib.Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re\dispatcher_callers.json")
out.write_text(json.dumps(msgs, ensure_ascii=False, indent=2), encoding='utf-8')
print(f"\nSaved to {out}")
