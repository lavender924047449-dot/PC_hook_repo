# verify_base.py -- 验证 WXWork.exe 模块基址与 0x11caaa0 地址有效性
import frida, subprocess, sys, time

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def get_main_pid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])

pid = get_main_pid()
print(f"PID = {pid}", flush=True)

JS = r"""
// 列出所有模块，找 WXWork.exe
var mods = Process.enumerateModules();
var main_mod = null;
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        main_mod = mods[i];
        break;
    }
}

if (main_mod) {
    send({type: 'mod', name: main_mod.name, base: main_mod.base.toString(),
          size: main_mod.size, path: main_mod.path});
} else {
    send({type: 'err', msg: 'WXWork.exe not found in module list'});
}

// 验证目标地址（文档声称的绝对地址）
var TARGET = ptr(0x11caaa0);
var RVA = 0x44AAA0;
var CLAIMED_BASE = ptr(0xD80000);

// 读前6字节（用于验证是函数序言还是垃圾数据）
var target_bytes = 'N/A';
try {
    var b = TARGET.readByteArray(16);
    target_bytes = Array.from(new Uint8Array(b)).map(function(x){
        return ('0'+x.toString(16)).slice(-2);
    }).join(' ');
} catch(e) {
    target_bytes = 'READ_ERROR: ' + e.message;
}

send({
    type: 'target',
    addr: TARGET.toString(),
    rva: '0x' + RVA.toString(16),
    claimed_base: CLAIMED_BASE.toString(),
    bytes: target_bytes
});

// 也验证文档中的其他已知地址
var known = [
    {name: 'SQL_builder', addr: 0x1023810, seq: '53 8b dc 83 ec 08'},
    {name: 'CGI_hotpath', addr: 0x1110b39},
    {name: 'dispatcher',  addr: 0x11caaa0, seq: '55 8b ec 6a ff 68'},
    {name: 'WSASend_wrap', addr: 0x11c93c0, seq: '55 8b ec'},
];
for (var j = 0; j < known.length; j++) {
    var k = known[j];
    var kb = 'ERR';
    try {
        var ba = ptr(k.addr).readByteArray(8);
        kb = Array.from(new Uint8Array(ba)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { kb = 'READ_ERROR'; }
    send({type:'known', name:k.name, addr:'0x'+k.addr.toString(16),
          expected: k.seq || '?', actual: kb});
}
"""

def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    t = p.get("type")
    if t == "mod":
        print(f"\n[WXWork.exe Module]", flush=True)
        print(f"  base = {p['base']}", flush=True)
        print(f"  size = {p['size']:,} bytes", flush=True)
        # 计算 0x11caaa0 的实际 RVA from this base
        base_int = int(p['base'], 16)
        target = 0x11caaa0
        actual_rva = target - base_int
        print(f"  actual RVA of 0x11caaa0 from this base: 0x{actual_rva:X}", flush=True)
        print(f"  (doc claimed RVA = 0x44AA A0, base = 0xD80000)", flush=True)
    elif t == "target":
        print(f"\n[Target 0x11caaa0]", flush=True)
        print(f"  bytes: {p['bytes']}", flush=True)
    elif t == "known":
        ok = "OK" if p.get("expected","?") in p.get("actual","") else "!!"
        print(f"\n[{ok}] {p['name']} @ {p['addr']}", flush=True)
        print(f"   expected: {p.get('expected','?')}", flush=True)
        print(f"   actual  : {p.get('actual','?')}", flush=True)
    elif t == "err":
        print(f"[ERR] {p.get('msg')}", flush=True)

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(3)
sc.unload()
sess.detach()
print("\n[+] done", flush=True)
