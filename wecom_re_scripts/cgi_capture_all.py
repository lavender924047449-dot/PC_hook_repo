# cgi_capture_all.py
# ─────────────────────────────────────────────────────────────────────
# 在 f2_top (RVA 0x963E58A，即 "before compress" 序列化点) 截获
# 所有 CGI send 调用，捕获明文 proto + 上下文
#
# 原理：
#   WXWork 所有 HTTP CGI 消息在发出前走此函数：
#     col::ChatRequestPackage  (args[2]) → 含 URL / CGI命令号 / 明文 payload
#   在 TLS + 应用层加密 **之前** ，proto 在此以明文存在。
#
# 用法：
#   1. 确保企微已登录
#   2. 运行本脚本
#   3. 在企微中 发一条文字消息 / 文件消息 / 转发消息
#   4. 脚本自动保存 JSON 到 runtime/wecom_re/
# ─────────────────────────────────────────────────────────────────────

import frida, subprocess, sys, os, time, threading, json, re
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

# ── 旧基址下 f2_top 绝对地址 ──────────────────────────────────────────
# 在 session base=0x2D0000 时，hook_plaintext.py 用 0x990e58a
# RVA = 0x990e58a - 0x2D0000 = 0x963E58A
F2_TOP_RVA = 0x963E58A     # 稳定，与 base 无关
CAPTURE_SEC = 90            # 90 秒观察窗口
MAX_CAP     = 50

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("未找到 :9882 LISTENING — 请先启动企微")

pid = get_pid()
print(f'[+] WXWork PID = {pid}', flush=True)

JS = r"""
'use strict';

var wxBase = Process.getModuleByName('WXWork.exe').base;
var F2_RVA  = 0x963E58A;
var hookPtr = wxBase.add(F2_RVA);

send({t:'init', base: wxBase.toString(), hook: hookPtr.toString()});

var captures = [];
var MAX = 50;
var NBYTES = 2048;  // 每个 ptr 最多读取字节数

function u32(p, off) {
    try { return p.add(off).readU32(); } catch(e) { return 0; }
}
function safeRead(addr, n) {
    try {
        var p = (typeof addr === 'number') ? ptr(addr) : addr;
        if (p.toUInt32() < 0x10000 || p.toUInt32() > 0xffff0000) return null;
        return Array.from(new Uint8Array(p.readByteArray(n)));
    } catch(e) { return null; }
}
function toHex(arr) {
    if (!arr) return '';
    return arr.map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join('');
}
function asAscii(arr) {
    if (!arr) return '';
    return arr.map(function(b){ return (b>=32&&b<127)?String.fromCharCode(b):'.'; }).join('');
}

// 从字节数组中提取所有 LE 32-bit 指针（可读范围内）
function extractPtrs(arr, maxRead) {
    var out = {};
    for (var i=0; i+3<arr.length; i+=4) {
        var v = arr[i] | (arr[i+1]<<8) | (arr[i+2]<<16) | (arr[i+3]<<24);
        var uv = v>>>0;
        if (uv < 0x10000 || uv > 0xffff0000) continue;
        var k = uv.toString(16);
        if (out[k]) continue;
        var d = safeRead(uv, maxRead);
        if (d) out[k] = d;
    }
    return out;
}

// 在字节数组中搜索有意义字符串
function findStrings(arr) {
    if (!arr) return [];
    var strs = [];
    // ASCII
    var run = '', runStart = 0;
    for (var i=0; i<arr.length; i++) {
        var b = arr[i];
        if (b>=32 && b<127) {
            if (run.length===0) runStart=i;
            run += String.fromCharCode(b);
        } else {
            if (run.length >= 6) strs.push({enc:'ascii', off:runStart, s:run});
            run = '';
        }
    }
    if (run.length>=6) strs.push({enc:'ascii', off:runStart, s:run});

    // UTF-16LE
    var u16='', u16start=0;
    for (var j=0; j+1<arr.length; j+=2) {
        var cp = arr[j] | (arr[j+1]<<8);
        if (cp>=32 && cp<0xd800) {
            if (u16.length===0) u16start=j;
            u16 += String.fromCharCode(cp);
        } else {
            if (u16.length>=6) strs.push({enc:'u16', off:u16start, s:u16});
            u16 = '';
        }
    }
    return strs;
}

// 在字节数组中扫描可能的 Protobuf（看起来合法的 tag/varint 结构）
function sniffProto(arr, maxFields) {
    var fields = [];
    var i = 0;
    while (i < arr.length && fields.length < maxFields) {
        if (arr[i] === 0) break;
        var tag_byte = arr[i++];
        var field = tag_byte >> 3;
        var wire  = tag_byte & 7;
        if (field === 0 || field > 512) break;
        try {
            if (wire === 0) { // varint
                var v=0,s=0;
                while(i<arr.length){var b=arr[i++];v|=(b&0x7f)<<s;s+=7;if(!(b&0x80))break;}
                fields.push({field:field, wire:0, val:v});
            } else if (wire === 2) { // length-delimited
                var len=0,s2=0;
                while(i<arr.length){var b2=arr[i++];len|=(b2&0x7f)<<s2;s2+=7;if(!(b2&0x80))break;}
                if (len<0 || len>65536 || i+len>arr.length) break;
                var payload = arr.slice(i, i+len);
                var ptext;
                try { ptext = payload.map(function(c){return c<128?String.fromCharCode(c):'?';}).join('');
                      ptext = ptext.replace(/[^\x20-\x7e]/g,'?'); } catch(e){ptext='';}
                fields.push({field:field, wire:2, len:len, text_hint:ptext.slice(0,80)});
                i += len;
            } else {
                break;
            }
        } catch(e) { break; }
    }
    return fields;
}

Interceptor.attach(hookPtr, {
    onEnter: function(args) {
        if (captures.length >= MAX) return;

        var cap = {ts: Date.now(), args: [], ptrDeref: {}, notes: []};

        // 读前 5 个 args
        for (var ai=0; ai<5; ai++) {
            try {
                var v = args[ai].toUInt32();
                cap.args.push(v.toString(16));
                if (v < 0x10000 || v > 0xffff0000) continue;
                // 读 2KB
                var d = safeRead(v, 2048);
                if (!d) continue;
                var dHex = toHex(d);
                var strs = findStrings(d);
                // 提取有意义字符串
                var notable = strs.filter(function(s){
                    return s.s.length > 8 &&
                           !s.s.match(/^[A-F0-9]+$/) &&
                           !s.s.match(/^[01.]+$/);
                }).slice(0,8);
                // 检测关键模式
                var joined = notable.map(function(x){return x.s;}).join('|');
                var hasURL = joined.indexOf('work.weixin.qq.com') >= 0 ||
                             joined.indexOf('weixin.qq.com') >= 0;
                var hasCGI = joined.indexOf('cgi request') >= 0 ||
                             joined.indexOf('compress') >= 0;
                var hasMsg = joined.indexOf('conversationId') >= 0 ||
                             joined.indexOf('msgId') >= 0 ||
                             joined.indexOf('ClientId') >= 0;

                // 跟随一层指针
                var lvl2 = extractPtrs(d, 512);
                var lvl2_strs = {};
                for (var k in lvl2) {
                    var ss = findStrings(lvl2[k]).filter(function(x){ return x.s.length>8; });
                    if (ss.length) lvl2_strs[k] = ss.slice(0,4).map(function(x){return x.s;});
                }

                cap.ptrDeref['arg'+ai] = {
                    addr: v.toString(16),
                    hex: dHex.slice(0,512),   // 前256字节 hex
                    notable: notable,
                    hasURL: hasURL,
                    hasCGI: hasCGI,
                    hasMsg: hasMsg,
                    lvl2: lvl2_strs,
                    proto: (d[0]>>3)>0 ? sniffProto(d, 15) : []
                };
                if (hasURL||hasCGI) cap.notes.push('arg'+ai+'=ChatRequestPkg?');
                if (hasMsg) cap.notes.push('arg'+ai+'=MsgCtx?');
            } catch(e) { cap.args.push('err:'+e.message); }
        }

        captures.push(cap);
        send({t:'hit', n:captures.length, notes:cap.notes, ts:cap.ts});
    }
});

recv('dump', function(_) {
    send({t:'dump', caps: captures});
});

send({t:'ready', rva: '0x'+F2_RVA.toString(16), hook: hookPtr.toString()});
"""

all_caps = []
dump_evt = threading.Event()

def on_msg(msg, data):
    if msg.get('type') == 'error':
        desc = msg.get('description','')[:300]
        stack = msg.get('stack','')[:200]
        print(f'[ERR] {desc}\n{stack}', flush=True)
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    t = p.get('t','')
    if t == 'init':
        print(f'[+] base={p.get("base")}  hook={p.get("hook")}', flush=True)
    elif t == 'ready':
        print(f'[+] HOOK READY @ {p.get("hook")}  (RVA {p.get("rva")})', flush=True)
    elif t == 'hit':
        notes = p.get('notes', [])
        flag = ' ← ' + ', '.join(notes) if notes else ''
        print(f'  [HIT #{p.get("n")}]{flag}', flush=True)
    elif t == 'dump':
        all_caps.extend(p.get('caps', []))
        dump_evt.set()

print('[*] Attaching...', flush=True)
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(2)

print(f'\n{"="*60}', flush=True)
print(f'🎯 请在 {CAPTURE_SEC} 秒内做以下操作：', flush=True)
print(f'   1. 在企微 发一条 文字消息（任意对话）', flush=True)
print(f'   2. 发一条 文件消息（拖文件到对话）', flush=True)
print(f'   3. 转发一条消息（右键→转发）', flush=True)
print(f'{"="*60}', flush=True)

time.sleep(CAPTURE_SEC)

sc.post({'type': 'dump'})
dump_evt.wait(timeout=15)
sc.unload()
sess.detach()

# ── 分析 ────────────────────────────────────────────────────────────────
print(f'\n[+] 共捕获 {len(all_caps)} 条', flush=True)

for i, cap in enumerate(all_caps):
    notes = cap.get('notes', [])
    print(f'\n{"─"*60}', flush=True)
    print(f'=== cap #{i+1}  ts={cap.get("ts")}  notes={notes}', flush=True)
    print(f'  args: {cap.get("args")}', flush=True)

    for akey, aval in cap.get('ptrDeref', {}).items():
        if not aval: continue
        addr = aval.get('addr','')
        notable = aval.get('notable', [])
        if notable:
            print(f'  [{akey} @ 0x{addr}]  hasURL={aval.get("hasURL")}  hasCGI={aval.get("hasCGI")}', flush=True)
            for ns in notable[:5]:
                print(f'    [{ns.get("enc")}+{ns.get("off")}] {ns.get("s","")[:100]!r}', flush=True)
        # 显示 proto 字段
        proto = aval.get('proto', [])
        if len(proto) >= 2:
            print(f'  [{akey}] proto_sniff: {proto[:6]}', flush=True)
        # 显示 lvl2 有意义字符串
        lvl2 = aval.get('lvl2', {})
        for paddr, strs2 in list(lvl2.items())[:4]:
            filtered = [s for s in strs2 if len(s)>8 and 'work.weixin' not in s]
            if filtered:
                print(f'    lvl2[0x{paddr}]: {filtered[:2]}', flush=True)

# ── 保存 ────────────────────────────────────────────────────────────────
ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
out_path = OUT_DIR / f'cgi_capture_{ts_str}.json'
out_path.write_text(json.dumps(all_caps, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out_path}', flush=True)

os._exit(0)
