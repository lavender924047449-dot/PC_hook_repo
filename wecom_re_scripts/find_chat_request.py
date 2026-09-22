"""
在内存中搜索 ChatRequestPackage + col:: 字符串
找到其 vtable/构造函数，并扫描可能的 Send/Build 方法
"""
import frida, subprocess, sys, os, time, threading, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID = {pid}', flush=True)

JS = r"""
'use strict';
var wxMod = Process.getModuleByName('WXWork.exe');
var wxBase = wxMod.base;
var wxSize = wxMod.size;

function scanStr(needle) {
    var CHUNK = 0x100000;
    var results = [];
    var cur = wxBase;
    var end = wxBase.add(wxSize);
    while (cur.compare(end) < 0) {
        var chunkEnd = cur.add(CHUNK);
        if (chunkEnd.compare(end) > 0) chunkEnd = end;
        try {
            var hits = Memory.scanSync(cur, chunkEnd.sub(cur).toInt32(), needle);
            hits.forEach(function(h) { results.push(h.address.toString()); });
        } catch(e) {}
        cur = chunkEnd;
    }
    return results;
}

// 搜索各种相关字符串
var searches = {
    'ChatRequestPackage': '43 68 61 74 52 65 71 75 65 73 74 50 61 63 6b 61 67 65',
    'col::ChatRequestPackage': '63 6f 6c 3a 3a 43 68 61 74 52 65 71 75 65 73 74',
    'ForwardMessage': '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65',
    'cgi request:1001': '63 67 69 20 72 65 71 75 65 73 74 3a 31 30 30 31',
    'SendMessage': '53 65 6e 64 4d 65 73 73 61 67 65',
    'before compress': '62 65 66 6f 72 65 20 63 6f 6d 70 72 65 73 73'
};

var results = {};
for (var key in searches) {
    results[key] = scanStr(searches[key]);
}

send({t:'scan_done', results: results});

// 针对 ChatRequestPackage 地址，找 xref（哪里 PUSH 这个地址）
// 在找到的字符串地址附近扫描 PUSH imm32
var chatPkgAddrs = results['ChatRequestPackage'] || [];
var xrefs = [];
chatPkgAddrs.forEach(function(strAddrStr) {
    var strAddr = parseInt(strAddrStr);
    // 搜索 68 XX XX XX XX 形式（PUSH imm32 = strAddr 附近）
    // 由于 VMP，直接搜可能失败
    // 改为：搜索 MovImm32 形式
    var lo = strAddr & 0xFF;
    var hi1 = (strAddr >> 8) & 0xFF;
    var hi2 = (strAddr >> 16) & 0xFF;
    var hi3 = (strAddr >> 24) & 0xFF;
    var pattern = [
        '68',
        ('0'+lo.toString(16)).slice(-2),
        ('0'+hi1.toString(16)).slice(-2),
        ('0'+hi2.toString(16)).slice(-2),
        ('0'+hi3.toString(16)).slice(-2)
    ].join(' ');
    var xr = scanStr(pattern);
    xr.forEach(function(a) { xrefs.push({str_addr: strAddrStr, ref_at: a}); });
});

send({t:'xrefs', xrefs: xrefs.slice(0, 20)});
"""

results = {}
xrefs = []
events = [threading.Event(), threading.Event()]

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description','')[:300], flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'scan_done':
        results.update(p.get('results', {}))
        events[0].set()
    elif t == 'xrefs':
        xrefs.extend(p.get('xrefs', []))
        events[1].set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
events[0].wait(timeout=120)
events[1].wait(timeout=30)

print('\n=== 字符串搜索结果 ===', flush=True)
for k, addrs in results.items():
    print('  [%s]: %d hits  %s' % (k, len(addrs), addrs[:3]), flush=True)

print('\n=== ChatRequestPackage PUSH xrefs ===', flush=True)
for x in xrefs[:10]:
    print('  str@%s  ref@%s' % (x.get('str_addr'), x.get('ref_at')), flush=True)

# 找 vtable：在 ChatRequestPackage 字符串地址附近 +/- 0x10，找一个 DWORD 指向代码段
wx_base = 0x2D0000  # approximate
print('\n=== 尝试找 vtable 附近 (ChatRequestPackage 前 -0x40..+0x40 字节) ===', flush=True)
for addr_str in results.get('ChatRequestPackage', [])[:5]:
    addr = int(addr_str, 16)
    rva = addr - wx_base
    print('  ChatRequestPackage @ 0x%x  RVA=0x%x' % (addr, rva), flush=True)

os._exit(0)
