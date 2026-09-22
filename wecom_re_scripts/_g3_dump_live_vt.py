# dump live vtable at inner this[0] from 171024 run (same PID/base)
import frida, subprocess, sys, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var base = mod.base;
function desc(p) {
    var v = p.toUInt32(), b = base.toUInt32();
    if (v >= b && v < b + mod.size) return 'wx+0x' + (v-b).toString(16);
    return '0x' + v.toString(16);
}
function dumpVt(addr, n) {
    var vt = ptr(addr);
    var slots = [];
    for (var i = 0; i < n; i++) {
        var fn = vt.add(i*4).readPointer();
        slots.push({i:i, off:'0x'+(i*4).toString(16), p:desc(fn), raw:'0x'+fn.toUInt32().toString(16)});
    }
    return slots;
}
// 171024 dump: this[0]=0xb065434  (same process, base 0x5e0000)
var live = 0xb065434;
var rva = live - base.toUInt32();
send({
    t:'vt',
    base:'0x'+base.toUInt32().toString(16),
    live:'0x'+live.toString(16),
    rva:'0x'+rva.toString(16),
    in_mod: (live>=base.toUInt32() && live<base.toUInt32()+mod.size),
    slots: dumpVt(live, 20)
});
// also dump file-expected: maybe this+0 is not aligned vtable start
// body this_hex started with d453060b = 0x0b0653d4
send({t:'vt2', live:'0xb0653d4', slots: dumpVt(0xb0653d4, 20)});
"""

pid = get_pid()
print(f'PID={pid}')
sess = frida.get_local_device().attach(pid)
got = []
def on_msg(msg, data):
    if msg.get('type')=='error':
        print('ERR', msg)
        return
    if msg.get('type')=='send':
        got.append(msg['payload'])
        p = msg['payload']
        print(json.dumps(p, ensure_ascii=False, indent=2)[:4000])
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
import time; time.sleep(0.3)
sc.unload(); sess.detach()
