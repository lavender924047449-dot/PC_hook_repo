"""
读取 0xb9114b 之后更多区域，找 sequence/send_time 写入点
同时分析已有数据：frame[5] 中的 ESI = [EBP-0x4C] 值
"""
import frida, time, json

sess = frida.attach(20632)
js = r"""
function hd(p, n) { try { return hexdump(ptr(p),{offset:0,length:n,header:false,ansi:false}); } catch(e){ return 'err:'+e.message; } }
function u32(p) { try { return ptr(p).readU32()>>>0; } catch(e){ return 0; } }
function s8(p, n) { try { return ptr(p).readUtf8String(n); } catch(e){ return ''; } }

// Read the SUCCESS PATH after JG at 0xb91155
// JG target = 0xb9115b + 0xA9 = 0xb91204
var success_path = hd(0xb91204, 200);

// Read the ZERO path continuation (after XORPS at 0xb91157)
var zero_path = hd(0xb91157, 200);

// Also: what does the function look like FURTHER along (after success path)?
// From 0xb9114b + 300 bytes
var extended = hd(0xb9114b + 200, 200);

// Frame[5] had EBP=0x18def7f8 (from the trace)
// The ESI value = [EBP-0x4C] = [0x18def7f8-0x4C] = [0x18def7ac]
// But these are stack addresses from a previous run (might be stale)
// Let's just read the code

// For frame[6] with EBP=0x18def88c
// The function at frame[6] is what calls the hooked function
// Let me find what function contains 0xb90b34 (CALL instruction in frame[6])

// Read the function containing 0xb90b34 more extensively
var func_b9 = hd(0xb90b00, 200);

// KEY: In the success path at 0xb91204, look for where sequence+send_time are written
// to the output struct

// Also check: what was at frame[6] arg a12 = 0x18def8b0?
// And frame[7] arg a8 = 0x18def920?
// These are stack addresses from the previous run and no longer valid
// Let's just read the code paths

send({
  success_path: success_path,
  zero_path: zero_path,
  extended: extended,
  func_b9: func_b9
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
    print("=== Success path at 0xb91204 (JG target) ===")
    for line in p.get('success_path', '').split('\n')[:20]:
        print(f"  {line}")
    
    print("\n=== Zero path at 0xb91157 ===")
    for line in p.get('zero_path', '').split('\n')[:20]:
        print(f"  {line}")
    
    print("\n=== Extended from 0xb9114b+200 ===")
    for line in p.get('extended', '').split('\n')[:15]:
        print(f"  {line}")
    
    print("\n=== Function at 0xb90b00 (contains CALL to hooked func) ===")
    for line in p.get('func_b9', '').split('\n')[:15]:
        print(f"  {line}")
