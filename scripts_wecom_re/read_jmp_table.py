"""
读取 dispatcher 跳转表并分析 case 2 的 CALL 目标
"""
import frida, time, sys, json

sess = frida.attach(20632)
js = r"""
function u32(p) { try { return p.readU32()>>>0; } catch(e){ return 0; } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return ''; } }

// Read jump table at 0x08B6BB78
var jt = ptr('0x08B6BB78');
var entries = [];
for (var i = 0; i <= 0x11; i++) {
  var addr = u32(jt.add(i*4));
  entries.push({c: i, a: '0x' + addr.toString(16)});
}

// Compute CALL1 target from case2 bytes
// At 0x8b6b5c9: e8 42 82 f3 f7
// next_ip = 0x8b6b5ce
var next_ip = 0x8b6b5ce;
var rel32 = 0xF7F38242;
var rel_signed = rel32 > 0x7FFFFFFF ? rel32 - 0x100000000 : rel32;
var target1 = (next_ip + rel_signed) >>> 0;

// Compute CALL2 target (if any) 
// At 0x8b6b5dc: e8 2f 4b d7 f9
var next_ip2 = 0x8b6b5e1;
var rel32_2 = 0xF9D74B2F;
var rel_signed2 = rel32_2 > 0x7FFFFFFF ? rel32_2 - 0x100000000 : rel32_2;
var target2 = (next_ip2 + rel_signed2) >>> 0;

// Dump case2 address bytes
var case2_dump = hd(ptr('0x8b6b5be'), 80);

// Dump target1 bytes
var t1_dump = hd(ptr(target1), 32);

// Dump bytes at 0x8b6b5d5 (after call1, looking for next call)
var after_call1_dump = hd(ptr('0x8b6b5ce'), 48);

send({
  entries: entries,
  case2_dump: case2_dump,
  target1: '0x' + target1.toString(16),
  t1_dump: t1_dump,
  target2: '0x' + target2.toString(16),
  t2_dump: hd(ptr(target2), 32),
  after_call1_dump: after_call1_dump
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
    print("=== Jump Table at 0x08B6BB78 ===")
    for e in p.get('entries', []):
        print(f"  case {e['c']:2d}: {e['a']}")
    print()
    print("=== Case2 bytes at 0x8b6b5be ===")
    print(p.get('case2_dump', ''))
    print()
    print(f"=== CALL1 target: {p.get('target1')} ===")
    print(p.get('t1_dump', ''))
    print()
    print(f"=== After CALL1 at 0x8b6b5ce ===")
    print(p.get('after_call1_dump', ''))
    print()
    print(f"=== CALL2 target: {p.get('target2')} ===")
    print(p.get('t2_dump', ''))
