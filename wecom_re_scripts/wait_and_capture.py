# wait_and_capture.py  
# 无限等待模式：等您转发，脚本自动触发、深度扫描，找 561B protobuf payload
# CGI_ITER 火了 → 立即深扫 args[1] + 所有指针 → 找 ForwardMessage proto

import frida, subprocess, sys, os, time, threading, json, re, struct
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID={pid}', flush=True)

CGI_ITER_RVA   = 0x390B39
F2_TOP_RVA     = 0x990E58A   # = wxBase.add(0x990e58a) 已验证可用

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
});
var wxBase = wx.base;
var CGI_ITER = wxBase.add(""" + hex(CGI_ITER_RVA) + r""");
var F2_TOP   = wxBase.add(""" + hex(F2_TOP_RVA)   + r""");

send({t:'info', base:wxBase.toString(), cgi:CGI_ITER.toString(), f2:F2_TOP.toString()});

var FWD_PATTERNS = {
    '01004179':1,'01006300':1,'01006c00':1,'01006d00':1,
    '01016135':1,'0161a92e':1,'01cbb414':1
};

function toB(p,n){try{return Array.from(new Uint8Array(ptr(p).readByteArray(n)));}catch(e){return [];}}
function toHex(p,n){return toB(p,n).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' ');}
function isAddr(v){return v>0x1000000 && v<0x7f000000;}

// BFS 指针追踪，找 proto 数据
function deepScan(root, depth) {
    var visited = {};
    var queue = [{p: root, d: 0, path: 'root'}];
    var results = [];
    while (queue.length > 0 && results.length < 30) {
        var item = queue.shift();
        var key = item.p.toString();
        if (visited[key] || item.d > depth) continue;
        visited[key] = 1;
        var bytes = toB(item.p, 512);
        if (bytes.length < 8) continue;
        // 尝试在每 4 字节边界找指针，最多检查 256B
        for (var off=0; off<Math.min(256, bytes.length-4); off+=4) {
            var sub = (bytes[off]) | (bytes[off+1]<<8) | (bytes[off+2]<<16) | (bytes[off+3]<<24);
            sub = sub >>> 0;
            if (isAddr(sub)) {
                var subB = toB(sub, 800);
                if (subB.length >= 8) {
                    // 判断是否像 protobuf：第一个字节的 wire type 和 field number
                    var b0 = subB[0]; var wire = b0 & 7; var field = b0 >> 3;
                    if (field >= 1 && field <= 100 && (wire === 0 || wire === 2 || wire === 5)) {
                        // 检查接下来几个字节也像 pb
                        var ok = true;
                        var i2 = 0;
                        // 尝试解析前 3 个字段
                        var nFields = 0;
                        var j = 0;
                        while (j < subB.length && nFields < 3) {
                            if (subB[j] === 0) { break; }
                            var tag2 = 0; var sh2 = 0;
                            while (j < subB.length) {
                                var bj = subB[j]; j++;
                                tag2 |= (bj & 0x7F) << sh2; sh2 += 7;
                                if (!(bj & 0x80)) break;
                                if (sh2 > 35) { ok = false; break; }
                            }
                            if (!ok) break;
                            var wire2 = tag2 & 7; var fld2 = tag2 >> 3;
                            if (fld2 === 0 || fld2 > 5000) break;
                            nFields++;
                            if (wire2 === 0) {
                                while (j < subB.length) { var bj2=subB[j]; j++; if (!(bj2&0x80)) break; }
                            } else if (wire2 === 2) {
                                var ln2 = 0; var sh3 = 0;
                                while (j < subB.length) { var bj3=subB[j]; j++; ln2|=(bj3&0x7F)<<sh3; sh3+=7; if(!(bj3&0x80)) break; }
                                if (ln2 > 50000 || j + ln2 > subB.length) break;
                                j += ln2;
                            } else if (wire2 === 5) { j += 4; }
                            else if (wire2 === 1) { j += 8; }
                            else break;
                        }
                        if (nFields >= 2) {
                            results.push({
                                path: item.path + '+0x' + off.toString(16),
                                addr: sub.toString(16),
                                hex: subB.map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' '),
                                depth: item.d
                            });
                        }
                    }
                    // 加入队列做下一层
                    if (item.d < depth) {
                        queue.push({p: ptr(sub), d: item.d+1, path: item.path+'+0x'+off.toString(16)+'→'});
                    }
                }
            }
        }
        // 找 ASCII 字符串
        var asc = '';
        for (var k2=0; k2<bytes.length-1; k2++) {
            if (bytes[k2] >= 0x20 && bytes[k2] <= 0x7e) { asc += String.fromCharCode(bytes[k2]); }
            else { 
                if (asc.length >= 8 && (asc.indexOf('cgi')>=0 || asc.indexOf('weixin')>=0 || asc.indexOf('forward')>=0 || asc.indexOf('compress')>=0 || asc.indexOf('http')>=0 || asc.indexOf('ChatRequest')>=0)) {
                    results.push({path: item.path+'[str@0x'+k2.toString(16)+']', addr: '?', hex: '', str: asc});
                }
                asc = '';
            }
        }
    }
    return results;
}

var captures = [];
var f2Captures = [];
var waiting = true;

// Hook F2_TOP
try {
    Interceptor.attach(F2_TOP, {
        onEnter: function(args) {
            if (f2Captures.length >= 20) return;
            var rec = {ts: Date.now(), args: []};
            for (var j=0; j<5; j++) {
                try {
                    var h = toHex(args[j], 512);
                    var str = '';
                    try { str = args[j].readCString(128) || ''; } catch(e){}
                    rec.args.push({v: args[j].toString(), h: h, str: str});
                } catch(e) { rec.args.push({v:'?'}); }
            }
            f2Captures.push(rec);
            send({t:'f2_hit', n: f2Captures.length});
        }
    });
    send({t:'hook_ok', name:'F2_TOP', addr: F2_TOP.toString()});
} catch(e) { send({t:'hook_err', name:'F2_TOP', msg:e.message}); }

// Hook CGI_ITER — 核心 hook
try {
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args) {
            try {
                var b4 = Array.from(new Uint8Array(args[1].readByteArray(4))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
                if (!FWD_PATTERNS[b4]) return;
                waiting = false;
                if (captures.length >= 20) return;
                var rec = {
                    ts: Date.now(),
                    compact: b4,
                    a1_hex: toHex(args[1], 1024),
                    scan: deepScan(args[1], 2)
                };
                captures.push(rec);
                send({t:'cgi_hit', compact: b4, n: captures.length, nscan: rec.scan.length});
            } catch(e) { send({t:'cgi_err', msg: e.message}); }
        }
    });
    send({t:'hook_ok', name:'CGI_ITER', addr: CGI_ITER.toString()});
} catch(e) { send({t:'hook_err', name:'CGI_ITER', msg:e.message}); }

recv('dump', function(_) {
    send({t:'dump_result', cgi: captures, f2: f2Captures});
});

send({t:'ready'});
"""

captures = []
f2_caps = []
dump_event = threading.Event()
first_hit = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info':
        print(f'  base={p["base"]}', flush=True)
        print(f'  CGI_ITER={p["cgi"]}', flush=True)
        print(f'  F2_TOP={p["f2"]}', flush=True)
    elif t == 'hook_ok':
        print(f'  [OK] {p["name"]} @ {p.get("addr","")}', flush=True)
    elif t == 'hook_err':
        print(f'  [HOOK_ERR] {p["name"]}: {p["msg"]}', flush=True)
    elif t == 'ready':
        print('[+] HOOKS READY — 请转发消息！（无时间限制，转发后自动收集 60 秒）', flush=True)
    elif t == 'cgi_hit':
        print(f'  ★ [CGI HIT #{p["n"]}] compact={p["compact"]} scan={p["nscan"]}', flush=True)
        first_hit.set()
    elif t == 'f2_hit':
        print(f'  [F2 HIT #{p["n"]}]', flush=True)
    elif t == 'dump_result':
        captures.extend(p.get('cgi', []))
        f2_caps.extend(p.get('f2', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print('\n' + '='*60)
print('★★★ 请在企微转发消息（无时间限制，等您操作）★★★')
print('='*60 + '\n', flush=True)

# 等第一次命中
first_hit.wait()
print('\n[+] 第一次命中！继续收集 30 秒...', flush=True)
time.sleep(30)

sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ────────────────────────────────────────────────────────────────────
def try_pb_decode(hexdata, limit=30):
    try: data = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    fields = []; i = 0
    while i < len(data) and len(fields) < limit:
        if i >= len(data) or data[i] == 0: break
        try:
            tag = 0; shift = 0
            while i < len(data):
                b = data[i]; i += 1
                tag |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
                if shift > 35: raise ValueError
            wire = tag & 7; field = tag >> 3
            if field == 0 or field > 5000: break
            if wire == 0:
                val = 0; sh2 = 0
                while i < len(data):
                    b = data[i]; i += 1
                    val |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                fields.append({'f':field,'t':'varint','v':val})
            elif wire == 2:
                ln = 0; sh2 = 0
                while i < len(data):
                    b = data[i]; i += 1
                    ln |= (b & 0x7F) << sh2; sh2 += 7
                    if not (b & 0x80): break
                if ln > 50000 or i+ln > len(data): break
                pay = data[i:i+ln]; i += ln
                try: s = pay.decode('utf-8'); fields.append({'f':field,'t':'str','v':s})
                except: fields.append({'f':field,'t':'bytes','len':ln,'hex':pay[:48].hex()})
            elif wire == 5: i += 4
            elif wire == 1: i += 8
            else: break
        except: break
    return fields

def find_strs_hex(hexdata, kws=None):
    kws = kws or ['forward','cgi','weixin','1001','before','compress','http','ChatRequest','msgid','seq','from','to']
    try: bs = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    results = []
    for m in re.finditer(rb'[\x20-\x7e]{5,}', bs):
        s = m.group().decode('ascii','ignore')
        if any(kw.lower() in s.lower() for kw in kws):
            results.append((m.start(), s))
    return results[:10]

print(f'\n[=== RESULTS ===]')
print(f'CGI caps: {len(captures)}  F2 caps: {len(f2_caps)}')

for ci, cap in enumerate(captures[:10]):
    print(f'\n══ CGI cap#{ci}  compact={cap.get("compact")} ══')
    # 直接字符串
    strs = find_strs_hex(cap.get('a1_hex',''))
    if strs:
        for off, ss in strs[:5]:
            print(f'  a1[+0x{off:03x}]: {ss[:100]}')
    
    # 扫描结果
    scan = cap.get('scan', [])
    print(f'  scan results: {len(scan)}')
    for s in scan[:10]:
        path = s.get('path','')
        addr = s.get('addr','')
        hexdata = s.get('hex','')
        sstr = s.get('str','')
        if sstr:
            print(f'  [STR] {path}: {sstr[:80]}')
        elif hexdata:
            fields = try_pb_decode(hexdata)
            if len(fields) >= 2:
                print(f'  [PROTO @ {path} → 0x{addr}] ({len(hexdata)//3}B)')
                for f in fields[:8]:
                    if f.get('t') == 'str':
                        print(f'    f{f["f"]}: {repr(f["v"][:80])}')
                    elif f.get('t') == 'bytes':
                        print(f'    f{f["f"]}(bytes,{f["len"]}B): {f["hex"][:24]}...')
                    else:
                        print(f'    f{f["f"]}={f["v"]}')
            else:
                print(f'  [PTR? @ {path} → 0x{addr}] hex={hexdata[:30]}...')

for ci, cap in enumerate(f2_caps[:5]):
    print(f'\n── F2 cap#{ci} ──')
    for ai, a in enumerate(cap.get('args',[])[:5]):
        s = a.get('str','')
        h = a.get('h','')
        strs = find_strs_hex(h)
        if s or strs:
            print(f'  arg[{ai}]={a.get("v","")}  str={s[:50]!r}')
            for off, ss in strs[:3]:
                print(f'    [+0x{off:03x}]: {ss[:100]}')
        # proto
        fields = try_pb_decode(h)
        if len(fields) >= 3:
            print(f'  arg[{ai}] [PROTO]')
            for f in fields[:8]:
                if f.get('t') == 'str':
                    print(f'    f{f["f"]}: {repr(f["v"][:80])}')
                elif f.get('t') == 'bytes':
                    print(f'    f{f["f"]}(bytes,{f["len"]}B): {f["hex"][:24]}')
                else:
                    print(f'    f{f["f"]}={f["v"]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'wait_cap_{ts}.json'
out.write_text(json.dumps({'cgi': captures, 'f2': f2_caps}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

os._exit(0)
