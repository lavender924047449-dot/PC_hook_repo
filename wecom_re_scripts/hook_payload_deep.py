# hook_payload_deep.py
# 在 f2_top(0x990e58a) 捕获含 CGI#1001 的请求，读 2048 字节 + 深度 deref
# 同时尝试 Protobuf 解码找 561 字节 plaintext

import frida, subprocess, sys, os, time, threading, json, re
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

# 查找 "before compress" 字符串地址（已知 0xb72e681）
BEFORE_COMPRESS_ADDR = 0xb72e681

JS = """
'use strict';
var HOOK_ADDR = 0x990e58a;
var BEFORE_COMPRESS_ADDR = """ + hex(BEFORE_COMPRESS_ADDR) + """;
var captures = [];
var MAX = 20;

function toHex(p, n) {
    try {
        var b = p.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return ''; }
}

function readCStr(p) {
    try { return p.readCString(256) || ''; } catch(e) { return ''; }
}

// 深度 2 层指针追踪
function followPtrs2(hexData, depth) {
    if (depth <= 0) return {};
    var bytes = hexData.split(' ').map(function(h){ return parseInt(h,16)||0; });
    var out = {};
    for (var i=0; i+3<bytes.length; i+=4) {
        var v = bytes[i]|(bytes[i+1]<<8)|(bytes[i+2]<<16)|(bytes[i+3]<<24);
        if (v > 0x100000 && v < 0x7fffffff) {
            var k = (v>>>0).toString(16);
            if (!out[k]) {
                var d = toHex(ptr(v>>>0), 512);
                if (d) {
                    out[k] = d;
                    // 第 2 层 deref（只取前 16 个指针）
                    if (depth > 1) {
                        var sub = followPtrs2(d, depth - 1);
                        for (var sk in sub) {
                            if (!out[sk]) out[sk] = sub[sk];
                        }
                    }
                }
            }
        }
    }
    return out;
}

Interceptor.attach(ptr(HOOK_ADDR), {
    onEnter: function(args) {
        if (captures.length >= MAX) return;
        var a2 = args[2];
        var a2i = a2.toInt32();
        if (a2i < 0x200000 || a2i > 0x7fffffff) return;

        // 读 2048 字节
        var a2_hex = toHex(a2, 2048);
        if (!a2_hex) return;

        // 检查 "before compress" 或 "after compress"
        var a2_str = a2_hex.replace(/ /g,'');
        var a2_bytes = [];
        for (var k=0; k<a2_str.length; k+=2) {
            a2_bytes.push(parseInt(a2_str.substr(k,2),16));
        }
        var ascii = a2_bytes.map(function(b){ return b>=32&&b<127?String.fromCharCode(b):'.'; }).join('');

        var hasBefore = ascii.indexOf('before compress') >= 0;
        var hasAfter  = ascii.indexOf('after compress') >= 0;
        var hasURL    = ascii.indexOf('i.work.weixin') >= 0;
        if (!hasBefore && !hasAfter && !hasURL) return;

        var ptrs = followPtrs2(a2_hex, 2);

        captures.push({
            ts: Date.now(),
            a2addr: a2.toString(),
            a2: a2_hex,
            hasBefore: hasBefore,
            hasAfter: hasAfter,
            ptrs: ptrs
        });
        send({t:'hit', n: captures.length, before: hasBefore, after: hasAfter, url: hasURL,
              addr: a2.toString()});
    }
});

recv('dump', function(_) {
    send({t:'dump_result', captures: captures});
});

send({t:'ready'});
"""

all_caps = []
dump_event = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description','')[:300], flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'ready':
        print('[+] Hook READY', flush=True)
    elif t == 'hit':
        flag = ''
        if p.get('before'): flag += '[BEFORE]'
        if p.get('after'): flag += '[AFTER]'
        if p.get('url'): flag += '[URL]'
        print('  [HIT#%d] %s  a2=%s' % (p.get('n'), flag, p.get('addr')), flush=True)
    elif t == 'dump_result':
        all_caps.extend(p.get('captures', []))
        dump_event.set()

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(1)

print('\n=== 请在 45 秒内转发消息！===', flush=True)
time.sleep(45)
sc.post({'type': 'dump'})
dump_event.wait(15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────

def try_protobuf(data_bytes, max_fields=20):
    """简单 Protobuf 解码"""
    fields = []
    i = 0
    while i < len(data_bytes) and len(fields) < max_fields:
        if data_bytes[i] == 0:
            break
        try:
            tag = 0
            shift = 0
            while True:
                b = data_bytes[i]; i += 1
                tag |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80): break
                if shift > 28: raise ValueError('varint too large')
            wire = tag & 7
            field = tag >> 3
            if field == 0: break
            if wire == 0:  # varint
                val = 0; shift = 0
                while True:
                    b = data_bytes[i]; i += 1
                    val |= (b & 0x7F) << shift
                    shift += 7
                    if not (b & 0x80): break
                fields.append({'field': field, 'type': 'varint', 'value': val})
            elif wire == 2:  # length-delimited
                length = 0; shift = 0
                while True:
                    b = data_bytes[i]; i += 1
                    length |= (b & 0x7F) << shift
                    shift += 7
                    if not (b & 0x80): break
                if length > 100000 or i + length > len(data_bytes):
                    break
                payload = bytes(data_bytes[i:i+length])
                i += length
                try:
                    s = payload.decode('utf-8', errors='strict')
                    fields.append({'field': field, 'type': 'string', 'value': s})
                except:
                    fields.append({'field': field, 'type': 'bytes', 'len': length,
                                   'hex': payload[:32].hex()})
            elif wire == 5:  # 32-bit
                val = data_bytes[i]|(data_bytes[i+1]<<8)|(data_bytes[i+2]<<16)|(data_bytes[i+3]<<24)
                i += 4
                fields.append({'field': field, 'type': 'fixed32', 'value': val})
            elif wire == 1:  # 64-bit
                i += 8
            else:
                break
        except:
            break
    return fields

print('\n[+] 共 %d 条 captures' % len(all_caps), flush=True)

for ci, cap in enumerate(all_caps):
    print('\n=== capture#%d  a2=%s  before=%s  after=%s ===' % (
        ci+1, cap['a2addr'], cap['hasBefore'], cap['hasAfter']), flush=True)
    
    a2b = bytes.fromhex(cap['a2'].replace(' ',''))
    # 找 "compress length (\d+)"
    a2_str = ''.join(chr(b) if 32<=b<127 else '.' for b in a2b)
    m = re.search(r'(before|after) compress length (\d+)', a2_str)
    if m:
        direction = m.group(1)
        length = int(m.group(2))
        print('  LOG: %s compress length=%d' % (direction, length), flush=True)
    
    # 打印 a2 前 320 字节
    for off in range(0, min(320, len(a2b)), 16):
        row = a2b[off:off+16]
        hx = ' '.join('%02x' % b for b in row)
        asc = ''.join(chr(b) if 32<=b<127 else '.' for b in row)
        print('  %04x: %-47s  %s' % (off, hx, asc), flush=True)
    
    # 在所有 deref 里搜索 Protobuf 格式数据
    print('  --- Protobuf search in deref ptrs ---', flush=True)
    pb_hits = []
    for addr_hex, hexd in cap.get('ptrs', {}).items():
        bs2 = bytes.fromhex(hexd.replace(' ',''))
        fields = try_protobuf(list(bs2))
        if len(fields) >= 3:  # 至少 3 个合法字段
            pb_hits.append((addr_hex, fields))
    
    for addr, flds in pb_hits[:5]:
        print('  [PB @0x%s] %d fields:' % (addr, len(flds)), flush=True)
        for f in flds[:8]:
            if f['type'] == 'string':
                print('    field%d: %r' % (f['field'], f['value'][:100]), flush=True)
            elif f['type'] == 'bytes':
                print('    field%d(bytes,len=%d): 0x%s...' % (f['field'], f['len'], f['hex'][:20]), flush=True)
            else:
                print('    field%d(%s)=%s' % (f['field'], f['type'], f['value']), flush=True)

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / ('payload_deep_%s.json' % ts)
out.write_text(json.dumps(all_caps, ensure_ascii=False, indent=2), encoding='utf-8')
print('\n[+] 保存:', out, flush=True)

os._exit(0)
