# read_proto_desc.py
# 读取 forward_msg 字符串在内存中的周边数据，
# 从 proto 描述符结构推导出 ForwardMessageReq 的字段和 CGI compact

import frida, subprocess, sys, time, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

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

function safeR(addr, n) {
    try { return Array.from(new Uint8Array(ptr(addr).readByteArray(n))); }
    catch(e) { return null; }
}

// forward_msg 的 3 处 VA
var fmVAs = [0xae89cd4, 0xb2a3d0c, 0xb2f5cc2];

var results = [];

fmVAs.forEach(function(va) {
    // 读 va 处及前后各 256 字节
    var before = safeR(va - 256, 512);
    var at = safeR(va, 64);
    
    // 尝试把 va-256 ~ va+256 里的每个4字节对齐位置读作指针，
    // 若指向已知字符串区域（rdata），则可能是 proto 描述符字段
    var ptrs_found = [];
    if (before) {
        for (var off = 0; off < before.length - 3; off += 4) {
            var pv = (before[off]) | (before[off+1]<<8) | (before[off+2]<<16) | (before[off+3]<<24);
            pv = pv >>> 0;
            // rdata 范围: wxBase + 0xa7fd000 ~ wxBase + 0xcb25000
            var lo = (wxBase.toInt32()>>>0) + 0xa7fd000;
            var hi = (wxBase.toInt32()>>>0) + 0xcb25000;
            if (pv >= lo && pv < hi) {
                // 读目标字符串
                try {
                    var s = ptr(pv).readCString();
                    if (s && s.length > 2 && s.length < 80) {
                        ptrs_found.push({off: off - 256, ptr: '0x'+pv.toString(16), s: s});
                    }
                } catch(e) {}
            }
        }
    }
    
    results.push({
        va: '0x'+va.toString(16),
        at_hex: at,
        ptrs: ptrs_found
    });
});

// 搜索 ForwardMessageReq 描述符结构
// 在 rdata 中搜索连续出现的 proto-like 模式：
// [string_ptr][field_num][wire_type]...
// 通过搜索 "ForwardMessageReq" 字符串引用来定位
var fmrVA = 0x0AD725E1;  // 已知 ForwardMessageReq VA
// 在 rdata 中搜索对 fmrVA 的引用（已知 text 段没有，再搜 rdata）
var rdataBase = wxBase.add(0xa7fd000);
var rdataSize = 0x2328000;
var pat = [fmrVA & 0xff, (fmrVA>>8)&0xff, (fmrVA>>16)&0xff, (fmrVA>>24)&0xff];
var patStr = pat.map(b => ('0'+b.toString(16)).slice(-2)).join(' ');

var xrefs = [];
try {
    var rs = Memory.scanSync(rdataBase, rdataSize, patStr);
    rs.forEach(function(r) {
        var xva = r.address.toInt32() >>> 0;
        var ctx = safeR(xva - 32, 128);
        xrefs.push({
            xva: '0x'+xva.toString(16),
            rva: '0x'+((xva - (wxBase.toInt32()>>>0)).toString(16)),
            ctx: ctx
        });
    });
} catch(e) {}

send({t: 'result', fmData: results, xrefs: xrefs});
"""

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'ERR: {msg.get("description","")}')
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    if p.get('t') == 'result':
        print('\n=== forward_msg 字符串周边分析 ===')
        for item in p['fmData']:
            print(f'\nVA={item["va"]}')
            at = item.get('at_hex')
            if at:
                bs = bytes(at)
                print(f'  内容: {bs.decode("utf-8", errors="replace")[:40]}')
            ptrs = item.get('ptrs', [])
            print(f'  周边字符串指针({len(ptrs)}):')
            for pt in ptrs:
                print(f'    off={pt["off"]:+d} ptr={pt["ptr"]} -> {repr(pt["s"][:60])}')
        
        print(f'\n=== ForwardMessageReq (0x0AD725E1) rdata XREF: {len(p["xrefs"])} 处 ===')
        for x in p['xrefs']:
            print(f'  xva={x["xva"]} rva={x["rva"]}')
            ctx = x.get('ctx')
            if ctx:
                bs = bytes(ctx)
                print(f'  ctx hex: {bs.hex()}')
                # 找字符串
                i = 0
                while i < len(bs) - 3:
                    pv = struct.unpack_from('<I', bs, i)[0]
                    if 0x0A700000 < pv < 0x0B500000:  # rdata 范围
                        try:
                            s = frida.get_local_device().enumerate_processes  # dummy
                        except: pass
                    i += 4

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(12)
sc.unload()
sess.detach()
