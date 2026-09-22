# find_msgtype_enum.py — 找 msgtype 枚举表
# 双管齐下：
#   A) 深 dump HIT #2 L2[10] 那个地址（0x318c88e8）附近 8KB，看 template/enum 结构
#   B) 在 .rdata 里搜 "text"/"voice"/"file" 相邻分布，找枚举字符串表

import frida, subprocess, sys, os, json
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
ts = datetime.now().strftime('%Y%m%d_%H%M%S')

# 想找的字符串（枚举 msgtype 名称）
TARGET_STRS = ['text', 'voice', 'file', 'image', 'video', 'link', 'location',
               'sysmsg', 'appmsg', 'card', 'sticker', 'emoji', 'silk',
               'amr', 'MMS', 'ChatContent']

JS = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');

function findSections() {
    var pe = mod.base;
    var ntOff = pe.add(0x3c).readU32();
    var nt = pe.add(ntOff);
    var numSec = nt.add(4 + 2).readU16();
    var szOpt = nt.add(4 + 16).readU16();
    var secHdr = nt.add(4 + 20 + szOpt);
    var sec = {};
    for (var i=0; i<numSec; i++) {
        var h = secHdr.add(i*40);
        var nb = new Uint8Array(h.readByteArray(8)); var name = '';
        for (var b=0; b<8 && nb[b]!==0; b++) name += String.fromCharCode(nb[b]);
        sec[name] = {base: mod.base.add(h.add(12).readU32()), size: h.add(8).readU32()};
    }
    return sec;
}
var secs = findSections();

function strHex(s) {
    var out = '';
    for (var i=0; i<s.length; i++) out += ('0'+s.charCodeAt(i).toString(16)).slice(-2) + ' ';
    return out.trim();
}

// 在 .rdata 搜 "\0word\0" (前后 null 保证是完整 C 串)
function scanStrict(s) {
    var pat = '00 ' + strHex(s) + ' 00';
    try {
        var hits = Memory.scanSync(secs['.rdata'].base, secs['.rdata'].size, pat);
        return hits.map(function(h){ return h.address.add(1); });  // +1 跳过前导 \0
    } catch(e) { return []; }
}

var targets = %TARGETS%;
var strMap = {};   // word → [addrs]

for (var ti=0; ti<targets.length; ti++) {
    var w = targets[ti];
    var addrs = scanStrict(w);
    strMap[w] = addrs.map(function(a){return a.toString();});
    send({t:'word', w: w, count: addrs.length, addrs: strMap[w].slice(0, 20)});
}

// 找"相邻聚集" —— 若两个字符串地址差 < 512B，可能是同一 enum 表
send({t:'phase2', msg: '相邻分析'});
var flatAddrs = [];  // [{addr:int, word:'text'}, ...]
for (var w in strMap) {
    for (var i=0; i<strMap[w].length; i++) {
        flatAddrs.push({addr: parseInt(strMap[w][i]), word: w});
    }
}
flatAddrs.sort(function(a,b){ return a.addr - b.addr; });

var clusters = [];
var curCluster = [];
for (var i=0; i<flatAddrs.length; i++) {
    if (curCluster.length === 0) {
        curCluster.push(flatAddrs[i]);
    } else {
        var last = curCluster[curCluster.length-1];
        if (flatAddrs[i].addr - last.addr < 256) {
            curCluster.push(flatAddrs[i]);
        } else {
            if (curCluster.length >= 3) clusters.push(curCluster);
            curCluster = [flatAddrs[i]];
        }
    }
}
if (curCluster.length >= 3) clusters.push(curCluster);

send({t:'clusters', count: clusters.length, data: clusters.map(function(c){
    return c.map(function(x){ return {a:'0x'+x.addr.toString(16), rva:'0x'+(x.addr - mod.base.toUInt32()).toString(16), w:x.word}; });
})});

// 找到最大 cluster：dump 那片区域周围 1KB
if (clusters.length > 0) {
    // 按 cluster 长度排序，取最大
    clusters.sort(function(a,b){return b.length - a.length;});
    var top = clusters[0];
    var minA = top[0].addr, maxA = top[top.length-1].addr;
    var startAddr = minA - 64;
    var dumpSize = Math.min(maxA - minA + 256, 4096);
    try {
        var raw = ptr(startAddr).readByteArray(dumpSize);
        var hex = '';
        var arr = new Uint8Array(raw);
        for (var i=0; i<arr.length; i++) hex += ('0'+arr[i].toString(16)).slice(-2);
        send({t:'cluster_dump', base:'0x'+startAddr.toString(16), size: dumpSize, hex: hex});
    } catch(e) { send({t:'err', e: String(e)}); }
}

send({t:'done'});
"""
JS = JS.replace('%TARGETS%', json.dumps(TARGET_STRS))

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line: return int(line.strip().split()[-1])
    raise RuntimeError('no pid')

done = {'v': False}
def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}', flush=True); return
    if msg.get('type') != 'send': return
    p = msg['payload']; t = p.get('t')
    if t == 'done': done['v'] = True; return
    if t == 'word':
        print(f'  {p["w"]!r:14s} × {p["count"]:3d}  first: {", ".join(p["addrs"][:3])}', flush=True)
    elif t == 'phase2':
        print(f'\n[+] {p["msg"]}...', flush=True)
    elif t == 'clusters':
        print(f'[+] 找到 {p["count"]} 个 >=3 词的聚集:', flush=True)
        for ci, cl in enumerate(p['data'][:5]):
            words = ', '.join([f'{x["w"]}@{x["rva"]}' for x in cl])
            print(f'  cluster[{ci}]: {words}', flush=True)
    elif t == 'cluster_dump':
        print(f'\n[+] Top cluster dump @ {p["base"]} ({p["size"]}B):', flush=True)
        raw = bytes.fromhex(p['hex'])
        # 打印 ASCII 视图
        for i in range(0, len(raw), 32):
            chunk = raw[i:i+32]
            asc = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in chunk)
            print(f'    {i:04x}: {chunk.hex():65s} {asc}', flush=True)
        # 落盘
        (OUT_DIR/f'msgtype_cluster_{ts}.bin').write_bytes(raw)

print('[*] PID...', flush=True)
pid = get_pid(); print(f'    PID={pid}', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS); sc.on('message', on_msg); sc.load()
import time
for _ in range(60):
    if done['v']: break
    time.sleep(1)
sc.unload(); sess.detach()
os._exit(0)
