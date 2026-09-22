"""
分析 lookup_bind_deep hook 点: 
- ret = 0xb9b0a4 -> CALL 在 0xb9b09f
- 找到 sqlite3_bind_int64 地址，hook 它来抓 message_id+结果
"""
import frida, time, json, pathlib, sys

PID = 20632
OUT = pathlib.Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re\bind_hook_analysis.json')

sess = frida.attach(PID)
js = r"""
function hd(p, n) { try { return hexdump(ptr(p),{offset:0,length:n,header:false,ansi:false}); } catch(e){ return 'err:'+e.message; } }
function u32(p) { try { return ptr(p).readU32()>>>0; } catch(e){ return 0; } }
function s8(p, n) { try { return ptr(p).readUtf8String(n); } catch(e){ return ''; } }

// 0xb9b0a4 is ret addr; CALL is at 0xb9b09f
// e8 xx xx xx xx at 0xb9b09f -> function at (0xb9b0a4 + rel32)
var call_bytes = hd(0xb9b09f, 10);

// Compute CALL target if it's e8 xx xx xx xx at 0xb9b09f
var byte0 = ptr(0xb9b09f).readU8();
var target_func = 0;
if (byte0 === 0xe8) {
  var rel32 = ptr(0xb9b09f+1).readS32();
  target_func = (0xb9b0a4 + rel32) >>> 0;
}

// Dump the target function
var func_dump = target_func ? hd(target_func, 80) : 'N/A';

// Also: look at the SQL string nearby - is 0xb9b09f inside a big function?
// Read more context: 200 bytes before the CALL
var context_before = hd(0xb9b09f - 100, 200);

// Try to find function prologue before 0xb9b09f
// Look for 55 8b ec pattern
var prologue_addr = 0;
for (var i = 0; i < 300; i++) {
  try {
    var b0 = ptr(0xb9b09f - i).readU8();
    var b1 = ptr(0xb9b09f - i + 1).readU8();
    var b2 = ptr(0xb9b09f - i + 2).readU8();
    if (b0 === 0x55 && b1 === 0x8b && b2 === 0xec) {
      prologue_addr = 0xb9b09f - i;
      break;
    }
  } catch(e) { break; }
}

// Also check what's at the hooked function (target_func)
var prev_ret_analysis = hd(0xb9b09f - 5, 15);

send({
  call_bytes: call_bytes,
  byte0: byte0,
  target_func: '0x' + target_func.toString(16),
  func_dump: func_dump,
  prologue_addr: '0x' + prologue_addr.toString(16),
  context_before: context_before.slice(0, 1000),
  prev_ret_analysis: prev_ret_analysis
});
"""

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
time.sleep(4)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print(f'CALL at 0xb9b09f: {p.get("call_bytes","")}')
    print(f'byte0=0x{p.get("byte0",0):02x}, target_func={p.get("target_func")}')
    print(f'prologue_addr={p.get("prologue_addr")}')
    print('\nTarget function dump:')
    for line in p.get('func_dump','').split('\n')[:10]:
        print(f'  {line}')
    print('\nContext before CALL (-100 bytes):')
    for line in p.get('context_before','').split('\n')[:15]:
        print(f'  {line}')
    OUT.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding='utf-8')
