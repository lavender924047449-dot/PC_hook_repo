# find_forward_func.py -- 在 WXWork 内存中搜索 ForwardMessageTo 字符串，定位代码地址
import frida, subprocess, sys, os, threading
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID = {pid}', flush=True)

done = threading.Event()
result = {}

def on_msg(msg, data):
    if msg.get('type') == 'send':
        result.update(msg['payload'])
    elif msg.get('type') == 'error':
        print('ERR:', msg['description'][:200], flush=True)
    done.set()

sess = frida.get_local_device().attach(pid)
JS = r"""
'use strict';
var wxBase = null;
var wxSize = 0;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxBase = mods[i].base;
        wxSize = mods[i].size;
        break;
    }
}

// 搜索 "ForwardMessageTo" ASCII bytes
// F=46 o=6f r=72 w=77 a=61 r=72 d=64 M=4d e=65 s=73 s=73 a=61 g=67 e=65 T=54 o=6f
var pattern = '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 54 6f';
var matches = [];
try {
    var found = Memory.scanSync(wxBase, wxSize, pattern);
    for (var k = 0; k < Math.min(found.length, 30); k++) {
        var addr = found[k].address;
        var rva = addr.sub(wxBase).toUInt32();
        var preview = '';
        try {
            var pb = addr.readByteArray(80);
            var pba = new Uint8Array(pb);
            var arr = [];
            for (var j = 0; j < pba.length; j++) {
                arr.push(('0' + pba[j].toString(16)).slice(-2));
            }
            preview = arr.join(' ');
        } catch(e) { preview = 'ERR:' + e.message; }
        matches.push([rva, addr.toString(), preview]);
    }
} catch(e) {
    matches.push([-1, 'ERR', e.message]);
}
send({matches: matches, wxBase: wxBase.toString()});
"""
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
done.wait(30)

print(f"wxBase: {result.get('wxBase')}", flush=True)
print(f"ForwardMessageTo 匹配数: {len(result.get('matches', []))}", flush=True)
for rva, abs_addr, preview in result.get('matches', []):
    print(f'\n  RVA=0x{rva:08x}  abs={abs_addr}', flush=True)
    # 解析为 ASCII
    try:
        bs = bytes.fromhex(preview.replace(' ', ''))
        s = bs.decode('ascii', errors='replace')[:70]
        print(f'  text: {s!r}', flush=True)
    except:
        print(f'  raw: {preview[:60]}', flush=True)

sess.detach()
os._exit(0)
