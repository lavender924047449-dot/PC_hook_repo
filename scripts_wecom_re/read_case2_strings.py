"""
分析 case2 中的 CALL 目标函数和字符串常量
"""
import frida, time, json

sess = frida.attach(20632)
js = r"""
function u32(p) { try { return p.readU32()>>>0; } catch(e){ return 0; } }
function s8(p, n) { try { return p.readUtf8String(n); } catch(e){ try { return p.readAnsiString(n); } catch(e2){ return ''; } } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return 'err:'+e.message; } }

// Read string at 0x0BC00E08 (pushed first in case2)
var s1 = s8(ptr('0x0BC00E08'), 80);
var s1_hex = hd(ptr('0x0BC00E08'), 32);

// Read string at 0x0D362CD4 (pushed before CALL2)
var s2 = s8(ptr('0x0D362CD4'), 80);
var s2_hex = hd(ptr('0x0D362CD4'), 32);

// Read string at 0x0D362CCC (pushed in block after)
var s3 = s8(ptr('0x0D362CCC'), 80);

// Dump more bytes of target2 (0x028E0110) to see full function
var t2_full = hd(ptr('0x028E0110'), 128);

// Also look at what 0x0AA3810 does more completely
var t1_full = hd(ptr('0x00AA3810'), 80);

// In case2, after the two CALLs (around 0x8b6b5ee), check the CALL at e8 a9 8a f3 f7
// Next_ip from 0x8b6b5f1 (after e8 a9 8a f3 f7 at 0x8b6b5ec)
// Actually: at 0x8b6b5f0 there's e8 a9 8a f3 f7
// 0x8b6b5f5 + 0xF7F38AA9 => ?
var ni3 = 0x8b6b5f5;
var r3 = 0xF7F38AA9;
var rs3 = r3 > 0x7FFFFFFF ? r3 - 0x100000000 : r3;
var t3 = (ni3 + rs3) >>> 0;
var t3_str = s8(ptr(t3), 8);

// at 0x8b6b5fb: e8 0d 4b d7 f9
var ni4 = 0x8b6b600;
var r4 = 0xF9D74B0D;
var rs4 = r4 > 0x7FFFFFFF ? r4 - 0x100000000 : r4;
var t4 = (ni4 + rs4) >>> 0;

// Key: what's at [ebp+8] when dispatcher is called? That's 'this' pointer (MessageTable*)
// Let's also hook the dispatcher and see actual args more carefully
// Actually let's hook 0x028E0110 to see what it's called with
send({
  s1: s1, s1_hex: s1_hex,
  s2: s2, s2_hex: s2_hex,
  s3: s3,
  t2_full: t2_full,
  t1_full: t1_full,
  call3_target: '0x' + t3.toString(16), call3_first8: t3_str,
  call4_target: '0x' + t4.toString(16)
});
"""

msgs = []
script = sess.create_script(js)
script.on('message', lambda m,d: msgs.append(m))
script.load()
time.sleep(3)
script.unload()
sess.detach()

for m in msgs:
    p = m.get('payload', {})
    print("=== String at 0x0BC00E08 ===")
    print("  str:", repr(p.get('s1', '')))
    print("  hex:", p.get('s1_hex', ''))
    print()
    print("=== String at 0x0D362CD4 ===")
    print("  str:", repr(p.get('s2', '')))
    print("  hex:", p.get('s2_hex', ''))
    print()
    print("=== String at 0x0D362CCC ===")
    print("  str:", repr(p.get('s3', '')))
    print()
    print("=== CALL1 at 0x00AA3810 full bytes ===")
    print(p.get('t1_full', ''))
    print()
    print("=== CALL2 at 0x028E0110 full bytes ===")
    print(p.get('t2_full', ''))
    print()
    print("call3 target:", p.get('call3_target'), "first8:", repr(p.get('call3_first8', '')))
    print("call4 target:", p.get('call4_target'))
