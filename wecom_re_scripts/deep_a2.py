# deep_a2.py
# Hook f2_top (0x990e58a)，深度读取 a2 上下文，找 561 字节 proto payload
# 已知：a2[0x0a8] = "cgi request:1001 before compress length 561"
# 策略：读 a2 前 512B，再追指针，找 proto

import frida, subprocess, sys, os, time, threading, json
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
print(f'[+] PID={pid}')

# f2_top 地址（WSASend 调用链顶层），转发时必触发
F2_TOP_RVA = 0x990E58A   # 之前验证正确
CGI_ITER_RVA = 0x390B39  # CGI 迭代器，转发时触发

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
});
var wxBase = wx.base;
var F2_TOP = wxBase.add(""" + hex(F2_TOP_RVA) + r""");
var CGI_ITER = wxBase.add(""" + hex(CGI_ITER_RVA) + r""");

send({t:'info', base: wxBase.toString(), f2: F2_TOP.toString()});

function safeHex(p, n) {
    try { return Array.from(new Uint8Array(ptr(p).readByteArray(n))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join(' '); }
    catch(e) { return ''; }
}

function safeStr(p) {
    try { return ptr(p).readCString(128); } catch(e) { return ''; }
}

function isHeapPtr(v) {
    return v > 0x1000000 && v < 0x7f000000 && (v & 3) === 0;
}

// 从地址开始扫描看起来像 Protobuf 的内容
function probePb(p, maxlen) {
    var limit = Math.min(maxlen, 2048);
    var h = safeHex(p, limit);
    if (!h) return null;
    var bs = h.replace(/ /g,'');
    // 尝试前几个字节判断是否像 PB：tag & wire
    var b0 = parseInt(bs.slice(0,2), 16);
    var wire = b0 & 7;
    var field = b0 >> 3;
    if (field >= 1 && field <= 100 && (wire === 0 || wire === 2)) {
        return {hex: h.slice(0, Math.min(limit*3, 561*3+200)), len: limit};
    }
    return null;
}

var caps = [];
var iterCaps = [];
var done = false;

// Hook A: f2_top — 读 args 0..4 及大量 deref
try {
    Interceptor.attach(F2_TOP, {
        onEnter: function(args) {
            if (done || caps.length >= 30) return;
            var rec = {ts: Date.now(), args: []};
            // 读 8 个参数
            for (var j=0; j<8; j++) {
                try {
                    var av = args[j];
                    var vi = av.toInt32();
                    var entry = {v: av.toString(), str: ''};
                    // 读直接内容（可能是字符串）
                    entry.str = safeStr(av);
                    // 读前 512B hex
                    entry.hex512 = safeHex(av, 512);
                    // 深扫：在 hex 中找 proto (扫 a=av+offset for offset=0,8,16,...,256)
                    entry.probes = [];
                    if (isHeapPtr(vi)) {
                        for (var off=0; off<512; off+=4) {
                            try {
                                var sub_ptr = av.add(off).readU32();
                                if (isHeapPtr(sub_ptr)) {
                                    var pb = probePb(sub_ptr, 800);
                                    if (pb) {
                                        entry.probes.push({off: off, ptr: sub_ptr.toString(16), hex: pb.hex});
                                    }
                                }
                            } catch(e) {}
                        }
                    }
                    rec.args.push(entry);
                } catch(e) { rec.args.push({v:'?'}); }
            }
            // 也读 ESP+0..ESP+32（栈上参数）
            try {
                rec.stack = safeHex(this.context.esp, 64);
            } catch(e) {}
            caps.push(rec);
            send({t:'f2_hit', n: caps.length});
        }
    });
    send({t:'hook_ok', name:'F2_TOP'});
} catch(e) { send({t:'hook_err', name:'F2_TOP', msg: e.message}); }

// Hook B: CGI_ITER — 只捕转发专属 pattern
var FWD_SET = {'01004179':1,'01006300':1,'01006c00':1,'01006d00':1,'01016135':1,'0161a92e':1,'01cbb414':1};
try {
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args) {
            try {
                var b = Array.from(new Uint8Array(args[1].readByteArray(4))).map(function(x){return ('0'+x.toString(16)).slice(-2)}).join('');
                if (!FWD_SET[b]) return;
                var rec = {ts: Date.now(), compact: b, hex: safeHex(args[1], 1024)};
                // 深扫 args[1] 的所有指针
                rec.probes = [];
                for (var off=0; off<256; off+=4) {
                    try {
                        var sub_ptr = args[1].add(off).readU32();
                        if (isHeapPtr(sub_ptr)) {
                            var pb = probePb(sub_ptr, 800);
                            if (pb) {
                                rec.probes.push({off: off, ptr: sub_ptr.toString(16), hex: pb.hex});
                            }
                        }
                    } catch(e) {}
                }
                iterCaps.push(rec);
                send({t:'cgi_hit', compact: b, n: iterCaps.length});
            } catch(e) {}
        }
    });
    send({t:'hook_ok', name:'CGI_ITER'});
} catch(e) { send({t:'hook_err', name:'CGI_ITER', msg: e.message}); }

recv('dump', function(_) {
    done = true;
    send({t:'dump_result', f2: caps, cgi: iterCaps});
});

send({t:'ready'});
"""

f2_caps = []
cgi_caps = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info':
        print(f'  base={p["base"]}  F2_TOP={p["f2"]}')
    elif t == 'hook_ok':
        print(f'  [OK] {p["name"]}')
    elif t == 'hook_err':
        print(f'  [ERR] {p["name"]}: {p["msg"]}')
    elif t == 'ready':
        print('[+] HOOKS READY')
    elif t == 'f2_hit':
        print(f'  [F2 HIT #{p["n"]}]')
    elif t == 'cgi_hit':
        print(f'  [CGI HIT #{p["n"]}] {p["compact"]}')
    elif t == 'dump_result':
        f2_caps.extend(p.get('f2', []))
        cgi_caps.extend(p.get('cgi', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print('='*60)
print('★★★ 请转发消息！★★★（等待 90 秒）')
print('='*60)

time.sleep(90)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────
import re, struct

def try_pb_decode(hexdata, limit=30):
    try: data = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    fields = []; i = 0
    while i < len(data) and len(fields) < limit:
        if data[i] == 0: break
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
                try: s=pay.decode('utf-8'); fields.append({'f':field,'t':'str','v':s})
                except: fields.append({'f':field,'t':'bytes','len':ln,'hex':pay[:48].hex()})
            elif wire == 5: i += 4
            elif wire == 1: i += 8
            else: break
        except: break
    return fields

def find_strs_hex(hexdata, min_len=5):
    try: bs = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    results = []
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, bs):
        results.append((m.start(), m.group().decode('ascii','ignore')))
    try:
        s16 = bs.decode('utf-16-le', errors='ignore')
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s16):
            results.append((m.start()*2, '[u16]'+m.group()))
    except: pass
    return results[:10]

print(f'\n[=== RESULTS ===]')
print(f'F2 caps: {len(f2_caps)}  CGI caps: {len(cgi_caps)}')

# 分析 F2 caps
for ci, cap in enumerate(f2_caps[:10]):
    print(f'\n── F2 cap#{ci} ──')
    for ai, arg in enumerate(cap.get('args', [])[:8]):
        h = arg.get('hex512','')
        s = arg.get('str','')
        probes = arg.get('probes', [])
        strs = find_strs_hex(h)
        useful = [(off,ss) for off,ss in strs if any(kw in ss.lower() for kw in ['before','after','cgi','weixin','forward','http','compress','1001'])]
        if useful:
            print(f'  arg[{ai}]={arg.get("v","?")}')
            for off, ss in useful[:4]:
                print(f'    [+0x{off:03x}] {ss[:100]}')
        # Protobuf probes
        for prob in probes[:5]:
            fields = try_pb_decode(prob['hex'])
            if len(fields) >= 4:
                print(f'  arg[{ai}]→[+0x{prob["off"]:02x}]→0x{prob["ptr"]} [PROTO len≈{len(prob["hex"])//3}B]')
                for f in fields[:8]:
                    if f.get('t') == 'str':
                        print(f'    field{f["f"]}: {repr(f["v"][:80])}')
                    elif f.get('t') == 'bytes':
                        print(f'    field{f["f"]}(bytes,{f["len"]}B): {f["hex"][:24]}...')
                    else:
                        print(f'    field{f["f"]}={f["v"]}')

# 分析 CGI caps
for ci, cap in enumerate(cgi_caps[:5]):
    print(f'\n── CGI cap#{ci} compact={cap.get("compact")} ──')
    # 直接 hex
    strs = find_strs_hex(cap.get('hex',''))
    for off, ss in strs[:6]:
        print(f'  hex[+0x{off:03x}]: {ss[:100]}')
    # probes
    for prob in cap.get('probes', [])[:8]:
        fields = try_pb_decode(prob['hex'])
        if len(fields) >= 3:
            print(f'  →[+0x{prob["off"]:02x}]→0x{prob["ptr"]} [PROTO len≈{len(prob["hex"])//3}B]')
            for f in fields[:6]:
                if f.get('t') == 'str':
                    print(f'    field{f["f"]}: {repr(f["v"][:80])}')
                elif f.get('t') == 'bytes':
                    print(f'    field{f["f"]}(bytes,{f["len"]}B): {f["hex"][:24]}...')
                else:
                    print(f'    field{f["f"]}={f["v"]}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'deep_a2_{ts}.json'
out.write_text(json.dumps({'f2': f2_caps, 'cgi': cgi_caps}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

os._exit(0)
