"""
分析 0x0D362CD4 指向的数据结构（传给 GetMessageSequenceAndTime 的参数）
+ 找到 SQLite step 函数地址
"""
import frida, time, json

sess = frida.attach(20632)
js = r"""
function u32(p) { try { return p.readU32()>>>0; } catch(e){ return 0; } }
function s8(p, n) { try { return p.readUtf8String(n); } catch(e){ try { return p.readAnsiString(n); } catch(e2){ return '(bin)'; } } }
function hd(p, n) { try { return hexdump(p,{offset:0,length:n,header:false,ansi:false}); } catch(e){ return 'err:'+e.message; } }
function looksPtr(v) { return v >= 0x00010000 && v < 0x7FFF0000; }

// Decode the data at 0x0D362CD4 (it's an array of pointers)
var base = ptr('0x0D362CD4');
var ptrs = [];
for (var i = 0; i < 8; i++) {
  var p = u32(base.add(i*4));
  var str = looksPtr(p) ? s8(ptr(p), 60) : '';
  ptrs.push({ i: i, addr: '0x' + p.toString(16), str: str });
}

// The function at 0x028E0110 calls 0x00AA6FB0
// Let's compute 0x00AA6FB0 target from bytes e8 7a 6e 1c fe at 0x028e0131
var ni_inner = 0x028e0131 + 5;  // 0x028e0136
var rel_inner = 0xFE1C6E7A;
var rs_inner = rel_inner > 0x7FFFFFFF ? rel_inner - 0x100000000 : rel_inner;
var target_inner = (ni_inner + rs_inner) >>> 0;

// Dump target_inner bytes
var ti_dump = hd(ptr(target_inner), 80);

// Also look for SQLite magic pattern
// sqlite3 handles typically have a pager magic at certain offset
// Look for string "SQLITE_" which sqlite3 stores internally
// Actually scan for "CREATE TABLE sqlite_" in memory which sqlite stores in schema

// Better: scan for sqlite3_step pattern - it starts with 55 8b ec and 
// does a bunch of work. But we don't know where it is.
// Let's try to find it by looking at what 0x00AA6FB0 does more carefully.

var aa_target_dump = hd(ptr(target_inner), 160);

// Also: read the actual inner CALL target from 0x028e0131
// e8 7a 6e 1c fe
// ni = 0x028e0136
// rel32 = 0xFE1C6E7A, signed = -0x01E39186
// target = 0x028e0136 - 0x01E39186 = ?

send({
  ptrs: ptrs,
  target_inner: '0x' + target_inner.toString(16),
  inner_dump: aa_target_dump
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
    print("=== 0x0D362CD4 pointer array ===")
    for e in p.get('ptrs', []):
        print(f"  [{e['i']}] {e['addr']} -> {repr(e['str'])}")
    print()
    print(f"=== Inner CALL target from 0x028E0110: {p.get('target_inner')} ===")
    print(p.get('inner_dump', ''))
