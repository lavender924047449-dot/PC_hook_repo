"""
分析调用帧地址，特别是 0xb9114b（高频 DB 访问点）附近的代码
"""
import frida, time, json

FRAMES = [0x8c68d57, 0x8c65929, 0x8beb258, 0x9449b6c, 0x9b66d9e, 0xb9114b, 0xb90b39, 0xc493f2]

sess = frida.attach(20632)
js = r"""
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return 'err:'+e.message; } }
function u32(p) { try { return p.readU32()>>>0; } catch(e){ return 0; } }
function s8(p, n) { try { return p.readUtf8String(n); } catch(e){ return ''; } }

// For each return address, dump: 40 bytes BEFORE (the CALL instruction), and 40 bytes AFTER
var frames = [0x8c68d57, 0x8c65929, 0x8beb258, 0x9449b6c, 0x9b66d9e, 0xb9114b, 0xb90b39, 0xc493f2];
var results = [];

for (var i = 0; i < frames.length; i++) {
  var addr = frames[i];
  // The ret address is just AFTER the CALL instruction
  // CALL is usually at ret_addr - 5 (for E8 rel32)
  var call_addr = addr - 5;
  var pre_dump = hd(ptr(call_addr - 40), 80); // 40 bytes before CALL + the CALL itself + 35 bytes after
  results.push({ addr: '0x'+addr.toString(16), pre_dump: pre_dump });
}

// Also dump 0xb9114b area more specifically: 80 bytes around it
var b9 = hd(ptr(0xb9114b - 60), 200);

// And check what sqlite3_step might look like: scan for SQLITE_ROW=100 comparison
// CMP EAX, 0x64 (100) = 83 f8 64
// Let's scan around the frame addresses for this pattern
var sqlite_row_hits = [];
for (var i = 0; i < frames.length; i++) {
  var addr = frames[i];
  try {
    var buf = ptr(addr - 200).readByteArray(400);
    var arr = new Uint8Array(buf);
    for (var j = 0; j < arr.length - 3; j++) {
      if (arr[j] === 0x83 && arr[j+1] === 0xf8 && arr[j+2] === 0x64) { // CMP EAX, 100
        sqlite_row_hits.push('0x' + (addr - 200 + j).toString(16) + ' @ frame[' + i + ']');
      }
      if (arr[j] === 0x3d && arr[j+1] === 0x64 && arr[j+2] === 0x00 && arr[j+3] === 0x00) { // CMP EAX, 0x64
        sqlite_row_hits.push('CMP_EAX_64_@ 0x' + (addr - 200 + j).toString(16) + ' frame[' + i + ']');
      }
    }
  } catch(e) {}
}

send({ results: results, b9_dump: b9, sqlite_row_hits: sqlite_row_hits });
"""

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
time.sleep(5)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print("=== Frame context dumps ===")
    for r in p.get('results', []):
        print(f"\n--- Around ret={r['addr']} (call_addr = {hex(int(r['addr'],16)-5)}) ---")
        for line in r['pre_dump'].split('\n'):
            print(f"  {line}")
    
    print("\n=== 0xb9114b area (±60 bytes) ===")
    for line in p.get('b9_dump', '').split('\n'):
        print(f"  {line}")
    
    print("\n=== SQLITE_ROW (CMP EAX,100) hits near frames ===")
    for h in p.get('sqlite_row_hits', []):
        print(f"  {h}")
