# read_descriptor.py: 读取 ForwardMessageReq 的完整 proto 描述符
# 已知: 0xad725e1 = ForwardMessageReq 开始, conv_proto 包
# 读取 4KB 完整序列 + 找 ForwardMessageReq 附近的字段描述符

import frida, subprocess, sys, os, time, json, re
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
OUT_DIR = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID={pid}')

# 关键地址（从之前扫描得到）
FWDREQ_ADDR  = 0xad725e1  # "ForwardMessageReq" 开始
FWDREQ2_ADDR = 0xb9c5290  # conv_proto.* 大表

JS = r"""
'use strict';
var results = {};

function hexDump(p, n) {
    try { return Array.from(new Uint8Array(ptr(p).readByteArray(n))); }
    catch(e) { return []; }
}

// 读 ForwardMessageReq 开始 8KB
results.fwdreq_8k = hexDump(""" + hex(FWDREQ_ADDR) + r""", 8192);

// 读 conv_proto 大表 8KB
results.conv_proto_8k = hexDump(""" + hex(FWDREQ2_ADDR) + r""", 8192);

// 找 ForwardMessage 源码路径完整版
var src_path_addr = """ + hex(0xad86c67) + r""";
results.source_path = hexDump(src_path_addr, 512);

// 读 HandleIMRef 上下文（含 fwid msgid 字段名）
var imref_addr = """ + hex(0xadde7c0) + r""";
results.imref_ctx = hexDump(imref_addr - 256, 2048);

// 扫描 ForwardMessageReq 所有 52 个实例，找 proto field 描述符
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
var hits = Memory.scanSync(wxBase, wx.size, '46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71');
results.all_fwdreq_hits = hits.slice(0, 10).map(function(h){
    return {addr: h.address.toString(), data: hexDump(h.address.sub(128), 640)};
});

send({t:'data', r: results});
"""

result_data = {}
done = __import__('threading').Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:300]}')
        done.set()
        return
    if msg.get('type') != 'send': return
    p = msg['payload']
    if p.get('t') == 'data':
        result_data.update(p.get('r', {}))
        done.set()

print('[*] Attaching...')
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on('message', on_message)
sc.load()
done.wait(timeout=30)
sess.detach()

# ─── 分析 ──────────────────────────────────────────────────────────────────────
def dump_strings(data_bytes, context=""):
    """找所有可读 ASCII 字符串，5+ 字符"""
    results = []
    bs = bytes(data_bytes)
    pos = 0
    while pos < len(bs):
        if bs[pos] >= 0x20 and bs[pos] <= 0x7e:
            start = pos
            while pos < len(bs) and bs[pos] >= 0x20 and bs[pos] <= 0x7e:
                pos += 1
            s = bs[start:pos].decode('ascii', 'ignore')
            if len(s) >= 4:
                results.append((start, s))
        else:
            pos += 1
    return results

def is_proto_name(s):
    """判断是否像 proto 字段/消息名"""
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', s)) and len(s) >= 3

print('\n[=== 分析 ForwardMessageReq 描述符表 ===]')

# 1. fwdreq_8k: 找所有 proto 名称
if 'fwdreq_8k' in result_data:
    bs = bytes(result_data['fwdreq_8k'])
    strs = dump_strings(bs)
    print(f'\n--- @0x{FWDREQ_ADDR:08x} 前 8KB 的字符串 ---')
    for off, s in strs:
        print(f'  +0x{off:04x}: {s[:100]}')

# 2. source_path
if 'source_path' in result_data:
    bs = bytes(result_data['source_path'])
    strs = dump_strings(bs)
    print(f'\n--- 源码路径 ---')
    for off, s in strs:
        print(f'  +0x{off:03x}: {s[:120]}')

# 3. imref_ctx: fwid msgid 上下文
if 'imref_ctx' in result_data:
    bs = bytes(result_data['imref_ctx'])
    strs = dump_strings(bs)
    print(f'\n--- HandleIMRef 上下文字符串（包含字段名） ---')
    for off, s in strs:
        if any(kw in s.lower() for kw in ['fwid','msgid','sendtime','serverid','conv_id','type','forward','message','error','param','result','handle']):
            print(f'  +0x{off:04x}: {s[:100]}')

# 4. conv_proto 大表
if 'conv_proto_8k' in result_data:
    bs = bytes(result_data['conv_proto_8k'])
    strs = dump_strings(bs)
    print(f'\n--- conv_proto.* 消息名列表 (前 60 个) ---')
    count = 0
    for off, s in strs:
        if ('conv_proto.' in s or s.startswith('Forward') or s.startswith('Single') or s.startswith('Get') or s.startswith('Decrypt')):
            print(f'  +0x{off:04x}: {s[:100]}')
            count += 1
            if count >= 60: break

# 5. all_fwdreq_hits - 找有字段名的 hit
print(f'\n--- ForwardMessageReq 10个实例分析 ---')
for i, hit in enumerate(result_data.get('all_fwdreq_hits', [])):
    bs = bytes(hit.get('data', []))
    strs = dump_strings(bs)
    addr = hit.get('addr','?')
    proto_strs = [s for _, s in strs if is_proto_name(s) and len(s) >= 3]
    if len(proto_strs) >= 3:
        print(f'\n  hit#{i} @{addr}:')
        for off, s in strs:
            if len(s) >= 3:
                print(f'    +0x{off:03x}: {s[:100]}')

# 保存
ts = int(time.time())
out = OUT_DIR / f'descriptor_{ts}.json'
# 只保存有意义的数据
save_data = {
    'source_path_strings': dump_strings(result_data.get('source_path',[])),
    'imref_strings': [(off, s) for off,s in dump_strings(result_data.get('imref_ctx',[])) 
                       if any(kw in s.lower() for kw in ['fwid','msgid','conv','type','message','forward'])],
    'conv_proto_messages': [(off, s) for off, s in dump_strings(result_data.get('conv_proto_8k',[]))
                             if 'conv_proto' in s or s.startswith(('Forward','Single','Get','Decrypt','Multi'))],
}
out.write_text(json.dumps(save_data, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')

os._exit(0)
