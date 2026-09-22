# verify_fwd_compact.py
# 验证 01414f32 是否是 ForwardMessage compact
# 同时捕获 01004179（备用）和 01414f32
# 用户转发后检查哪个 compact 触发

import frida, subprocess, sys, os, time, threading, json, struct
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])

pid = get_pid()
print(f'PID={pid}')

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
var wxBase = wx.base;
send({t:'info', base: wxBase.toString()});

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

// 目标 compact: 01414f32 (新候选) + 01004179 (老 compact)
var TARGETS = {
    '01414f32': true,
    '01004179': true,
    '01ed4135': false  // TLS cert, 排除
};

var captures = [];
var hitEvent = false;
var hitCount = 0;
var MAX = 5;

// CGI_ITER at RVA 0x390B39
var CGI_ITER = wxBase.add(0x390B39);
try {
    Interceptor.attach(CGI_ITER, {
        onEnter: function(args) {
            try {
                var compact = '';
                try {
                    var b = new Uint8Array(args[1].readByteArray(4));
                    compact = ('0'+b[0].toString(16)).slice(-2)+('0'+b[1].toString(16)).slice(-2)
                            + ('0'+b[2].toString(16)).slice(-2)+('0'+b[3].toString(16)).slice(-2);
                } catch(e) {}

                if (!TARGETS[compact]) return;
                if (hitCount >= MAX) return;
                hitCount++;

                // 读 args[0..5]
                var argPtrs = [], argData = {};
                for (var i = 0; i < 6; i++) {
                    try {
                        var v = args[i].toInt32() >>> 0;
                        argPtrs.push('0x'+v.toString(16));
                        if (i <= 4) {
                            argData['arg'+i] = safeR(v, 512);
                        }
                    } catch(e) { argPtrs.push('0x0'); }
                }

                // 深度读: 遍历 a1 的前 10 个指针偏移，读每个指针目标
                var a1v = args[1].toInt32() >>> 0;
                var nested = {};
                for (var off = 0; off <= 0x40; off += 4) {
                    try {
                        var pv = ptr(a1v + off).readU32() >>> 0;
                        if (pv > 0x10000000 && pv < 0x7FFFFFFF) {
                            var d = safeR(pv, 256);
                            if (d) nested['a1+0x'+off.toString(16)] = {ptr:'0x'+pv.toString(16), data:d};
                            // 二层
                            for (var off2 = 0; off2 <= 0x40; off2 += 4) {
                                try {
                                    var pv2 = ptr(pv + off2).readU32() >>> 0;
                                    if (pv2 > 0x10000000 && pv2 < 0x7FFFFFFF) {
                                        var d2 = safeR(pv2, 256);
                                        if (d2) nested['a1+0x'+off.toString(16)+'→+0x'+off2.toString(16)] = {ptr:'0x'+pv2.toString(16), data:d2};
                                    }
                                } catch(e) {}
                            }
                        }
                    } catch(e) {}
                }

                captures.push({n:hitCount, compact:compact, args:argPtrs, argData:argData, nested:nested});
                send({t:'hit', n:hitCount, compact:compact, args:argPtrs.slice(0,4)});
            } catch(e) {}
        }
    });
    send({t:'ok', fn:'CGI_ITER'});
} catch(e) { send({t:'fail', fn:'CGI_ITER', m:e.message}); }

recv('dump', function(_) { send({t:'dump', caps:captures}); });
send({t:'ready'});
"""

captures = []
dump_event = threading.Event()
hit_event = threading.Event()

def on_msg(msg, data):
    if msg.get('type') == 'error': return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info': print(f'  wxBase={p["base"]}')
    elif t == 'ok': print(f'  [OK] {p["fn"]}')
    elif t == 'fail': print(f'  [FAIL] {p["fn"]}: {p["m"]}')
    elif t == 'ready':
        print('[+] HOOKS READY!')
        print('\n' + '='*60)
        print('请在企微转发消息！')
        print('  等待: 01414f32 (新候选) 或 01004179 (老 compact)')
        print('='*60)
    elif t == 'hit':
        print(f'  ★ HIT! compact={p["compact"]} n={p["n"]} args={p["args"]}')
        hit_event.set()
    elif t == 'dump':
        captures.extend(p.get('caps', []))
        dump_event.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(2)

got = hit_event.wait(timeout=300)
if not got:
    print('[!] 300s 超时')
    os._exit(1)

time.sleep(3)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ─────────────────────────────────────────────────────────────────────
def decode_varint(bs, pos):
    v = 0; sh = 0
    while pos < len(bs):
        b = bs[pos]; pos += 1; v |= (b&0x7F)<<sh; sh += 7
        if not(b&0x80): return v, pos
    return None, pos

def parse_proto(bs):
    fields = []; i = 0
    while i < len(bs) and len(fields) < 40:
        if bs[i] == 0: break
        try:
            tag, i = decode_varint(bs, i)
            if tag is None: break
            w = tag&7; fn = tag>>3
            if fn==0 or fn>5000: break
            if w==0:
                v,i = decode_varint(bs,i)
                if v is None: break
                fields.append((fn,'v',v))
            elif w==2:
                ln,i2 = decode_varint(bs,i)
                if ln is None or ln>200000 or i2+ln>len(bs): break
                pay=bs[i2:i2+ln]; i=i2+ln
                try: fields.append((fn,'s',pay.decode('utf-8')))
                except: fields.append((fn,'b',pay))
            elif w==5:
                if i+4<=len(bs):
                    v=struct.unpack_from('<I',bs,i)[0]; i+=4; fields.append((fn,'i32',v))
                else: break
            elif w==1:
                if i+8<=len(bs):
                    v=struct.unpack_from('<Q',bs,i)[0]; i+=8; fields.append((fn,'i64',v))
                else: break
            else: break
        except: break
    return fields

print(f'\n[=== {len(captures)} 次捕获 ===]')
for ci, cap in enumerate(captures):
    print(f'\n{"="*65}')
    print(f'Cap #{ci}: compact={cap["compact"]} args={cap["args"]}')

    # 分析 nested
    nested = cap.get('nested', {})
    print(f'  nested keys ({len(nested)}): 找含 proto 的...')
    interesting = []
    for path, info in sorted(nested.items()):
        if not info.get('data'): continue
        bs = bytes(info['data'])
        pf = parse_proto(bs)
        if len(pf) >= 2:
            # 有 proto，检查是否含 f13
            has_f13 = any(fn==13 for fn,_,_ in pf)
            marker = ' ★ f13!' if has_f13 else ''
            interesting.append((path, info['ptr'], pf, marker))

    for path, ptr_addr, pf, marker in interesting[:10]:
        print(f'\n  path={path} ptr={ptr_addr}{marker}')
        for fn, wt, v in pf[:12]:
            if wt=='v': print(f'    f{fn}={v} (0x{v:x})')
            elif wt=='s': print(f'    f{fn}={repr(v[:60])}')
            elif wt=='b': print(f'    f{fn}=bytes[{len(v)}]:{v[:8].hex()}')
            elif wt=='i32': print(f'    f{fn}=i32:{v}')
            elif wt=='i64': print(f'    f{fn}=i64:{v}')

ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'verify_fwd_{ts}.json'
out.write_text(json.dumps(captures, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
