# find_fmr_va.py - 在运行时内存中找 ForwardMessageReq 的 VA，并搜索 XREF
import frida, subprocess, sys, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def get_pid():
    o = subprocess.run(['netstat','-ano'],capture_output=True,text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l: return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(m => m.name.toLowerCase()==='wxwork.exe');
var wxBase = wx.base;

// 搜索 rdata 段
var SEARCH_START = wxBase.add(0xa7fd000);
var SEARCH_SIZE = 0x2400000;

var pat = '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71';  // ForwardMessageReq
var results = Memory.scanSync(SEARCH_START, SEARCH_SIZE, pat);

if(results.length > 0){
    var r = results[0];
    var va = r.address.toInt32() >>> 0;
    var rva = r.address.sub(wxBase).toInt32() >>> 0;
    send({t:'found', va:'0x'+va.toString(16), rva:'0x'+rva.toString(16)});
    
    // 读 80 字节
    var nearby = Array.from(new Uint8Array(r.address.readByteArray(80)));
    send({t:'data', bytes: nearby});
    
    // XREF 搜索
    var vaB = [va&0xff,(va>>8)&0xff,(va>>16)&0xff,(va>>24)&0xff];
    var xrefPat = vaB.map(b=>('0'+b.toString(16)).slice(-2)).join(' ');
    try{
        var xrefs = Memory.scanSync(wxBase, 0xa7fd000, xrefPat);
        var addrs = xrefs.slice(0,8).map(x=>'0x'+(x.address.toInt32()>>>0).toString(16));
        var rvas = xrefs.slice(0,8).map(x=>'0x'+(x.address.sub(wxBase).toInt32()>>>0).toString(16));
        send({t:'xrefs', count:xrefs.length, addrs:addrs, rvas:rvas});
    }catch(e){ send({t:'xerr', m:e.message}); }
} else {
    send({t:'notfound'});
}
send({t:'done'});
"""

def on_msg(msg, data):
    if msg.get('type')=='send':
        p = msg['payload']
        t = p.get('t','')
        if t=='found':
            print(f'ForwardMessageReq VA={p["va"]} RVA={p["rva"]}')
        elif t=='data':
            bs = bytes(p['bytes'])
            print(f'  数据: {bs.hex()}')
            print(f'  文本: {bs[:20]}')
        elif t=='xrefs':
            print(f'XREF 数量: {p["count"]}')
            for a, r in zip(p['addrs'], p['rvas']):
                print(f'  addr={a} RVA={r}')
        elif t=='xerr':
            print(f'XREF ERR: {p["m"]}')
        elif t=='notfound':
            print('未找到 ForwardMessageReq')
        elif t=='done':
            print('完成')

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(8)
sc.unload()
sess.detach()
