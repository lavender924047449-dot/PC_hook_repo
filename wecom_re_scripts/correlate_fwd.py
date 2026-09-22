# correlate_fwd.py
# 同时 hook WSASend + 0x390CE0
# WSASend 触发时记录时间戳，向前找最近一次 0x390CE0 调用 → 这就是转发
# 从那次调用的 args[4]/args[5] 深度读取 compact

import frida, subprocess, sys, os, time, json, threading
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
var wxBase = wx.base;
var ws2 = Process.getModuleByName('ws2_32.dll');

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

var startTs = Date.now();
var cgiCalls = [];
var wsaHits  = [];
var MAX_CGI  = 1000;
var hits     = [];

// ── Hook 0x390CE0 ──
Interceptor.attach(wxBase.add(0x390ce0), {
    onEnter: function(args) {
        if (cgiCalls.length >= MAX_CGI) return;
        var ts = Date.now() - startTs;
        var begin = args[1].toInt32() >>> 0;
        var end   = args[2].toInt32() >>> 0;
        var bufSz = (end > begin && end - begin < 2048) ? end - begin : 0;
        var buf   = safeR(begin, Math.min(bufSz, 128));
        var a4    = args[4].toInt32() >>> 0;
        var a5    = args[5].toInt32() >>> 0;
        
        // 深度扫描 a4/a5：每个4字节对齐位置读4字节
        var a4_scan = safeR(a4, 128);
        var a5_scan = safeR(a5, 128);
        
        cgiCalls.push({ts:ts, begin:'0x'+begin.toString(16), bufSz:bufSz,
                       buf:buf, a4:'0x'+a4.toString(16), a5:'0x'+a5.toString(16),
                       a4_scan:a4_scan, a5_scan:a5_scan});
    }
});

// ── Hook WSASend ──
var wsaSend = null;
ws2.enumerateExports().forEach(function(e) {
    if (e.name === 'WSASend') wsaSend = e.address;
});
if (wsaSend) {
    Interceptor.attach(wsaSend, {
        onEnter: function(args) {
            var ts = Date.now() - startTs;
            var bufLen = 0;
            var bufHex = '';
            try {
                var lpBuffers = args[1];
                bufLen = lpBuffers.readU32();
                if (bufLen > 0 && bufLen < 65536) {
                    var bufPtr = lpBuffers.add(4).readPointer();
                    var d = new Uint8Array(bufPtr.readByteArray(Math.min(bufLen, 64)));
                    bufHex = Array.from(d).map(b => ('0'+b.toString(16)).slice(-2)).join('');
                }
            } catch(e) {}
            wsaHits.push({ts:ts, bufLen:bufLen, buf:bufHex});
            send({t:'wsa', ts:ts, bufLen:bufLen, buf:bufHex.slice(0,32)});
        }
    });
    send({t:'info', m:'WSASend hooked @ ' + wsaSend.toString()});
}

send({t:'ready'});

recv('dump', function(_) {
    send({t:'dump', cgiCalls:cgiCalls.slice(-500), wsaHits:wsaHits});
});
"""

ready_event = threading.Event()
dump_event  = threading.Event()
all_data    = {}
wsa_ts_list = []

def on_msg(msg, data):
    if msg.get('type') == 'error': print(f'ERR: {msg.get("description","")}'); return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  {p["m"]}')
    elif t == 'ready': ready_event.set()
    elif t == 'wsa':
        wsa_ts_list.append(p['ts'])
        print(f'  ★★★ WSASend! t={p["ts"]/1000:.2f}s len={p["bufLen"]} buf={p["buf"][:16]}')
    elif t == 'dump':
        all_data['cgi'] = p['cgiCalls']
        all_data['wsa'] = p['wsaHits']
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
ready_event.wait(10)

print('\n[10s 预热 + 等待转发]')
print('='*60)
print('*** 请在企微转发一条消息！（60s 窗口）***')
print('='*60)
time.sleep(60)

sc.post({'type':'dump'})
dump_event.wait(15)

cgi_calls = all_data.get('cgi', [])
wsa_hits  = all_data.get('wsa', [])
print(f'\n[结果] CGI calls: {len(cgi_calls)}, WSASend hits: {len(wsa_hits)}')

def hex16(r):
    buf = r.get('buf')
    return bytes(buf[:16]).hex() if buf else '?'*32

def scan_compact(scan_bytes):
    """在 scan 字节数组中找所有形如 01 XX XX XX 的模式"""
    if not scan_bytes: return []
    found = []
    bs = scan_bytes
    for i in range(0, len(bs)-3, 4):
        if bs[i] == 0x01:
            found.append((i, bytes(bs[i:i+4]).hex()))
    return found

# 对每次 WSASend，找 200ms 内最近的 0x390CE0 调用
for wsa in wsa_hits:
    wt = wsa['ts']
    print(f'\n★ WSASend @ t={wt/1000:.2f}s buf={wsa["buf"]}')
    # 找 wt-300ms 到 wt 之间的 CGI 调用
    nearby = [(abs(c['ts']-wt), c) for c in cgi_calls if abs(c['ts']-wt) < 500]
    nearby.sort()
    if not nearby:
        print('  !! 无对应 CGI 调用 (±500ms)')
        continue
    print(f'  最近 CGI 调用 (前5):')
    for delta, c in nearby[:5]:
        print(f'    delta={delta:+d}ms begin={c["begin"]} buf={hex16(c)[:16]}')
        # 扫描 compact
        for scan_name, scan_data in [('a4', c.get('a4_scan')), ('a5', c.get('a5_scan')), ('buf', c.get('buf'))]:
            compacts = scan_compact(scan_data)
            if compacts:
                print(f'      {scan_name} compact patterns: {compacts}')
            # 打印扫描区的原始 hex
            if scan_data:
                print(f'      {scan_name}[{c.get("a4" if scan_name=="a4" else "a5" if scan_name=="a5" else "begin")}] = {bytes(scan_data[:16]).hex()}')

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT / f'correlate_fwd_{ts}.json'
out.write_text(json.dumps({'cgi': cgi_calls[-100:], 'wsa': wsa_hits}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

sc.unload()
sess.detach()
os._exit(0)
