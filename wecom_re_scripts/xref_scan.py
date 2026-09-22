# xref_scan.py - 全模块扫描 ForwardMessageReq 的引用地址
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
var wx = Process.enumerateModules().find(m=>m.name.toLowerCase()==='wxwork.exe');
var wxBase = wx.base;
var wxSize = wx.size;

var fmrVA = 0x0AD725E1;
var vaLE = [fmrVA&0xff,(fmrVA>>8)&0xff,(fmrVA>>16)&0xff,(fmrVA>>24)&0xff];
var patStr = vaLE.map(b=>('0'+b.toString(16)).slice(-2)).join(' ');

var found = [];
var CHUNK = 0x8000000;  // 128MB chunks
var pos = wxBase.toInt32() >>> 0;
var end = pos + (wxSize >>> 0);

while(pos < end && found.length < 20){
    var chunkSize = Math.min(CHUNK, end - pos);
    try{
        var rs = Memory.scanSync(ptr(pos), chunkSize, patStr);
        rs.forEach(function(r){
            var va = r.address.toInt32() >>> 0;
            var rva = va - (wxBase.toInt32() >>> 0);
            found.push({va:'0x'+va.toString(16), rva:'0x'+rva.toString(16)});
        });
    }catch(e){}
    pos += chunkSize;
}

// 也搜索 forward_msg 的 VA
var idx2 = Memory.scanSync(wxBase.add(0xa7fd000), 0x2400000, '66 6f 72 77 61 72 64 5f 6d 73 67');
var f2 = idx2.slice(0,3).map(function(r){
    var va = r.address.toInt32()>>>0;
    return {va:'0x'+va.toString(16), rva:'0x'+(va-(wxBase.toInt32()>>>0)).toString(16)};
});

send({t:'result', found:found, forward_msg:f2});
"""

def on_msg(msg, data):
    if msg.get('type')=='send':
        p = msg['payload']
        if p.get('t')=='result':
            f = p['found']
            print(f'ForwardMessageReq XREF: {len(f)} 处')
            for r in f:
                print(f'  VA={r["va"]} RVA={r["rva"]}')
            fm = p.get('forward_msg', [])
            print(f'\nforward_msg string: {len(fm)} 处')
            for r in fm:
                print(f'  VA={r["va"]} RVA={r["rva"]}')

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(20)
sc.unload()
sess.detach()
