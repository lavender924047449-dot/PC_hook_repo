# final_capture.py
# 综合捕获：重启后自动找新 base，挂 3 个 hook，只需用户转发一次
# Hook A: CGI 迭代器 (RVA 0x390B39) - 已验证 100% 可靠，读消息 ID
# Hook B: CGI builder (RVA 0x99235A0) - 读 561 字节 Protobuf payload
# Hook C: 内存监控 "before compress" 页 - 确认 builder 地址

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

# 已知 RVA（基于之前 base=0x2D0000）
RVA_CGI_ITER   = 0x390B39   # CGI 迭代器 hook 点
RVA_CGI_BLDPRE = 0x99235A0  # CGI builder 函数 prologue（含 "before compress"）
RVA_BEFORE_STR = 0xB45E681  # "before compress" 字符串 RVA

FWD_SET = ['01004179','01006300','01006c00','01006d00','01016135','0161a92e','01cbb414']

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
});
var wxBase = wx.base;
var wxSize = wx.size;

// 计算各 hook 地址
var HOOK_ITER   = wxBase.add(""" + hex(RVA_CGI_ITER)   + r""");
var HOOK_BLD    = wxBase.add(""" + hex(RVA_CGI_BLDPRE) + r""");
var STR_BEFORE  = wxBase.add(""" + hex(RVA_BEFORE_STR) + r""");

send({t:'info', base: wxBase.toString(), size: '0x'+wxSize.toString(16),
     iter: HOOK_ITER.toString(), bld: HOOK_BLD.toString(),
     str_before: STR_BEFORE.toString()});

// ── 工具函数 ─────────────────────────────────────────────────────────────────
function toHex(p, n) {
    try {
        var b = p.readByteArray(n);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join(' ');
    } catch(e) { return ''; }
}

var FWD_SET = {
    '01004179':1,'01006300':1,'01006c00':1,'01006d00':1,
    '01016135':1,'0161a92e':1,'01cbb414':1
};

function compact4(ptr_) {
    try {
        var b = ptr_.readByteArray(4);
        return Array.from(new Uint8Array(b)).map(function(x){
            return ('0'+x.toString(16)).slice(-2);
        }).join('');
    } catch(e) { return ''; }
}

// ── Hook A: CGI 迭代器 ─────────────────────────────────────────────────────
var cgi_captures = [];
try {
    Interceptor.attach(HOOK_ITER, {
        onEnter: function(args) {
            if (cgi_captures.length >= 200) return;
            var c = compact4(args[1]);
            if (!FWD_SET[c]) return;
            var a1 = toHex(args[1], 512);
            // 读 EBP 处（需要 context）
            var ebp = this.context.ebp;
            var ebp_54 = toHex(ebp.sub(0x54), 64);
            cgi_captures.push({ts: Date.now(), compact: c, a1: a1, ebp_54: ebp_54});
            send({t:'cgi_hit', compact: c, n: cgi_captures.length});
        }
    });
    send({t:'hook_ok', name:'CGI_ITER', addr: HOOK_ITER.toString()});
} catch(e) {
    send({t:'hook_err', name:'CGI_ITER', msg: e.message});
}

// ── Hook B: CGI builder function prologue ──────────────────────────────────
var bld_captures = [];
try {
    Interceptor.attach(HOOK_BLD, {
        onEnter: function(args) {
            if (bld_captures.length >= 50) return;
            var ctx = this.context;
            var rec = {
                ts: Date.now(),
                regs: {
                    eax: ctx.eax.toString(), ecx: ctx.ecx.toString(),
                    edx: ctx.edx.toString(), ebx: ctx.ebx.toString(),
                    esp: ctx.esp.toString(), ebp: ctx.ebp.toString(),
                    esi: ctx.esi.toString(), edi: ctx.edi.toString()
                }
            };
            // 读 args[0..7] 及其 deref
            rec.args = [];
            for (var j=0; j<8; j++) {
                try {
                    var av = args[j].toInt32();
                    var s = '';
                    var h = '';
                    if (av > 0x100000 && av < 0x7fffffff) {
                        try { s = ptr(av).readCString(64) || ''; } catch(e) {}
                        h = toHex(ptr(av), 512);
                    }
                    rec.args.push({v: av.toString(16), s: s, h: h});
                } catch(e) { rec.args.push({v:'?'}); }
            }
            bld_captures.push(rec);
            send({t:'bld_hit', n: bld_captures.length,
                  ecx: ctx.ecx.toString(), esi: ctx.esi.toString()});
        }
    });
    send({t:'hook_ok', name:'CGI_BLD', addr: HOOK_BLD.toString()});
} catch(e) {
    send({t:'hook_err', name:'CGI_BLD', msg: e.message});
}

// ── Hook C: MemoryAccessMonitor on "before compress" page ─────────────────
var str_accesses = [];
var monitorPage = STR_BEFORE.and(ptr(0xFFFFF000));
try {
    MemoryAccessMonitor.enable([{base: monitorPage, size: 0x1000}], {
        onAccess: function(details) {
            if (str_accesses.length >= 50) return;
            var from_rva = parseInt(details.from.toString()) - parseInt(wxBase.toString());
            str_accesses.push({
                from: details.from.toString(),
                rva: '0x' + from_rva.toString(16),
                op: details.operation
            });
            if (str_accesses.length === 1) {
                send({t:'str_access', from: details.from.toString(),
                      rva: '0x' + from_rva.toString(16)});
            }
        }
    });
    send({t:'hook_ok', name:'MEM_MONITOR', page: monitorPage.toString()});
} catch(e) {
    send({t:'hook_err', name:'MEM_MONITOR', msg: e.message});
}

recv('dump', function(_) {
    send({t:'dump_result',
          cgi: cgi_captures,
          bld: bld_captures,
          str_acc: str_accesses});
});

send({t:'ready'});
"""

cgi_caps = []
bld_caps = []
str_acc = []
dump_event = threading.Event()
first_hit = threading.Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:300]}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'info':
        print(f'  WXWork base={p.get("base")}  size={p.get("size")}', flush=True)
        print(f'  CGI_ITER={p.get("iter")}', flush=True)
        print(f'  CGI_BLD={p.get("bld")}', flush=True)
        print(f'  STR_BEFORE={p.get("str_before")}', flush=True)
    elif t == 'hook_ok':
        print(f'  [OK] {p.get("name")} @ {p.get("addr") or p.get("page")}', flush=True)
    elif t == 'hook_err':
        print(f'  [HOOK_ERR] {p.get("name")}: {p.get("msg")}', flush=True)
    elif t == 'ready':
        print('[+] ALL HOOKS READY', flush=True)
    elif t == 'cgi_hit':
        print(f'  [CGI HIT #{p.get("n")}] compact={p.get("compact")}', flush=True)
        first_hit.set()
    elif t == 'bld_hit':
        print(f'  [BLD HIT #{p.get("n")}] ECX={p.get("ecx")} ESI={p.get("esi")}', flush=True)
    elif t == 'str_access':
        print(f'  [MEM HIT] from={p.get("from")} RVA={p.get("rva")}', flush=True)
    elif t == 'dump_result':
        cgi_caps.extend(p.get('cgi', []))
        bld_caps.extend(p.get('bld', []))
        str_acc.extend(p.get('str_acc', []))
        dump_event.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
time.sleep(2)

print(f'\n{"="*60}', flush=True)
print('★★★ 请立即在企微转发任意消息！★★★', flush=True)
print('  右键消息 → 转发 → 选联系人 → 发送', flush=True)
print('  可以重复转发多次（脚本等待 90 秒）', flush=True)
print(f'{"="*60}\n', flush=True)

time.sleep(90)
sc.post({'type': 'dump'})
dump_event.wait(timeout=15)

# ─── 分析 ──────────────────────────────────────────────────────────────────────
def find_strs(hexdata, min_len=5):
    if not hexdata: return []
    try: bs = bytes.fromhex(hexdata.replace(' ',''))
    except: return []
    results = []
    for enc, codec in [('u8','utf-8'),('u16','utf-16-le')]:
        s = bs.decode(codec, errors='ignore')
        for m in re.finditer(r'[\x20-\x7e\u4e00-\u9fff]{%d,}' % min_len, s):
            w = m.group().strip()
            if w: results.append((enc, w))
    return results[:8]

def try_pb(raw):
    """简单 Protobuf 解码"""
    fields = []; i = 0; data = list(raw)
    while i < len(data) and len(fields) < 30:
        if data[i] == 0: break
        try:
            tag = 0; shift = 0
            while True:
                b = data[i]; i += 1
                tag |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
                if shift > 35: raise ValueError
            wire = tag & 7; field = tag >> 3
            if field == 0 or field > 10000: break
            if wire == 0:
                val = 0; shift = 0
                while True:
                    b = data[i]; i += 1
                    val |= (b & 0x7F) << shift; shift += 7
                    if not (b & 0x80): break
                fields.append({'f': field, 't': 'varint', 'v': val})
            elif wire == 2:
                ln = 0; shift = 0
                while True:
                    b = data[i]; i += 1
                    ln |= (b & 0x7F) << shift; shift += 7
                    if not (b & 0x80): break
                if ln > 10000 or i + ln > len(data): break
                pay = bytes(data[i:i+ln]); i += ln
                try: s = pay.decode('utf-8', errors='strict'); fields.append({'f':field,'t':'str','v':s})
                except: fields.append({'f':field,'t':'bytes','len':ln,'hex':pay[:32].hex()})
            elif wire == 5: i += 4
            elif wire == 1: i += 8
            else: break
        except: break
    return fields

print(f'\n{"="*60}', flush=True)
print(f'[=== 结果 ===]', flush=True)
print(f'CGI hits: {len(cgi_caps)}  BLD hits: {len(bld_caps)}  STR accesses: {len(str_acc)}', flush=True)

# CGI 分析
if cgi_caps:
    print(f'\n--- CGI 迭代器捕获（转发专属） ---', flush=True)
    by_compact = {}
    for r in cgi_caps:
        by_compact.setdefault(r['compact'], []).append(r)
    for pat, recs in sorted(by_compact.items()):
        if pat == '01cbb414': continue
        print(f'  [{pat}] {len(recs)} 条', flush=True)
        r = recs[0]
        a1b = bytes.fromhex(r['a1'].replace(' ',''))
        # 找消息 ID
        import struct
        for off in range(0, min(256, len(a1b)), 2):
            try:
                s = a1b[off:off+40].decode('utf-16-le', errors='strict')
                if re.match(r'\d+:\d+:\d', s):
                    print(f'    msgId: {s.split(chr(0))[0]!r}')
                    break
            except: pass
        # deref 0x70
        if len(a1b) > 0x74:
            ptr_val = struct.unpack_from('<I', a1b, 0x70)[0]
            print(f'    [0x70] ptr=0x{ptr_val:08x}', flush=True)

# BLD 分析
if bld_caps:
    print(f'\n--- CGI Builder 捕获 ---', flush=True)
    for i, cap in enumerate(bld_caps[:5]):
        print(f'\n  BLD#{i+1}  ECX={cap["regs"]["ecx"]} ESI={cap["regs"]["esi"]}', flush=True)
        for j, a in enumerate(cap.get('args', [])):
            s = a.get('s','')
            strs = find_strs(a.get('h',''))
            useful = [(e,ss) for e,ss in strs if not re.search(r'\.xml|weclaw|bubble', ss)]
            if s or useful:
                print(f'    arg[{j}]=0x{a.get("v","?")}  str={s[:50]!r}', flush=True)
                for enc, ss in useful[:3]:
                    print(f'      [{enc}] {ss[:100]!r}', flush=True)
            # 尝试 Protobuf
            h = a.get('h','')
            if h:
                try:
                    raw = bytes.fromhex(h.replace(' ',''))
                    pb = try_pb(raw)
                    if len(pb) >= 3:
                        print(f'    [Protobuf @ arg[{j}]]', flush=True)
                        for f in pb[:8]:
                            if f.get('t') == 'str':
                                print(f'      field{f["f"]}: {f["v"][:80]!r}', flush=True)
                            elif f.get('t') == 'bytes':
                                print(f'      field{f["f"]}(bytes,len={f["len"]}): {f["hex"][:16]}', flush=True)
                            else:
                                print(f'      field{f["f"]}(varint)={f["v"]}', flush=True)
                except: pass

# STR 访问
if str_acc:
    print(f'\n--- "before compress" 字符串访问（可能是新 builder 地址） ---', flush=True)
    wx_base = int(sess._impl.pid and '0', 16) or 0  # will update below
    for a in str_acc[:5]:
        print(f'  from={a.get("from")} RVA={a.get("rva")}', flush=True)

# 保存
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
out = OUT_DIR / f'final_capture_{ts}.json'
out.write_text(json.dumps({
    'cgi': cgi_caps, 'bld': bld_caps, 'str_acc': str_acc
}, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}', flush=True)

os._exit(0)
