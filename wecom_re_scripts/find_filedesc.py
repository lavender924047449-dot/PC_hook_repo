# find_filedesc.py: 找 crtxcgi.proto 的 FileDescriptorProto 二进制
# proto 文件描述符通过 InternalAddGeneratedFile 注册
# 格式：字符串 "\n\x0ecrtxcgi.proto\x12\x04CRTX..." (binary protobuf)

import frida, subprocess, sys, os, time, json, re, struct
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

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
var wxSize = wx.size;
var results = {};

// 搜索 "crtxcgi.proto" 字符串（proto 文件名出现在 FileDescriptorProto 的 name 字段）
var crtx_pattern = '63 72 74 78 63 67 69 2e 70 72 6f 74 6f';  // "crtxcgi.proto"
var crtx_hits = Memory.scanSync(wxBase, wxSize, crtx_pattern);
results.crtx_hits = crtx_hits.slice(0,5).map(function(h){
    return {addr: h.address.toString(),
            data: Array.from(new Uint8Array(h.address.sub(32).readByteArray(2048)))};
});

// 搜索 "ftn_cgi.proto"
var ftn_pattern = '66 74 6e 5f 63 67 69 2e 70 72 6f 74 6f';  // "ftn_cgi.proto"
var ftn_hits = Memory.scanSync(wxBase, wxSize, ftn_pattern);
results.ftn_hits = ftn_hits.slice(0,5).map(function(h){
    return {addr: h.address.toString(),
            data: Array.from(new Uint8Array(h.address.sub(32).readByteArray(2048)))};
});

// 搜索 "conv_proto" 包（已知在 conv_proto 命名空间）
var conv_pattern = '63 6f 6e 76 5f 70 72 6f 74 6f';  // "conv_proto"
var conv_hits = Memory.scanSync(wxBase, wxSize, conv_pattern);
results.conv_hits_count = conv_hits.length;
results.conv_hits = conv_hits.slice(0,5).map(function(h){
    return {addr: h.address.toString(),
            data: Array.from(new Uint8Array(h.address.sub(32).readByteArray(512)))};
});

// 搜索 "ForwardMessageReq" 的完整二进制 proto 描述符
// 在 FileDescriptorProto 中，消息名存为: 0x0a [len] "ForwardMessageReq"
// 0x0a = field 1 (name), wire type 2 (LEN)
// len("ForwardMessageReq") = 18 = 0x12
// 所以搜索: 0a 12 46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71
var fwd_desc_pattern = '0a 12 46 6f 72 77 61 72 64 4d 65 73 73 61 67 65 52 65 71';
var fwd_desc_hits = Memory.scanSync(wxBase, wxSize, fwd_desc_pattern);
results.fwd_desc_hits = fwd_desc_hits.slice(0,5).map(function(h){
    return {addr: h.address.toString(),
            data: Array.from(new Uint8Array(h.address.sub(64).readByteArray(1024)))};
});

// 也搜索 ForwardMessageRsp 的字段描述符 (field name 在 FileDescriptorProto 里)
// field: 0x0a [field_name_len] [field_name]
// FieldDescriptorProto.name = field 1
// FieldDescriptorProto.number = field 3
// FieldDescriptorProto.type = field 5
// 搜索字段名 "msg_list": 0a 08 6d 73 67 5f 6c 69 73 74
var msg_list_pat = '0a 08 6d 73 67 5f 6c 69 73 74';  // field name "msg_list"
var ml_hits = Memory.scanSync(wxBase, wxSize, msg_list_pat);
results.msg_list_hits = ml_hits.slice(0,5).map(function(h){
    return {addr: h.address.toString(),
            data: Array.from(new Uint8Array(h.address.sub(32).readByteArray(512)))};
});

// 搜索字段名 "to_username"
var to_user_pat = '0a 0b 74 6f 5f 75 73 65 72 6e 61 6d 65';  // "to_username"
var tu_hits = Memory.scanSync(wxBase, wxSize, to_user_pat);
results.to_username_hits = tu_hits.slice(0,5).map(function(h){
    return {addr: h.address.toString(),
            data: Array.from(new Uint8Array(h.address.sub(32).readByteArray(512)))};
});

// 搜索字段名 "from_username"
var from_user_pat = '0a 0d 66 72 6f 6d 5f 75 73 65 72 6e 61 6d 65';  // "from_username"
var fu_hits = Memory.scanSync(wxBase, wxSize, from_user_pat);
results.from_username_hits = fu_hits.slice(0,5).map(function(h){
    return {addr: h.address.toString(),
            data: Array.from(new Uint8Array(h.address.sub(32).readByteArray(512)))};
});

// 搜索单条消息中的关键字段: new_msg_id, msg_type, content_type 等
// "new_msg_id" = 0a 0a 6e 65 77 5f 6d 73 67 5f 69 64
var new_msg_id_pat = '0a 0a 6e 65 77 5f 6d 73 67 5f 69 64';
var nmi_hits = Memory.scanSync(wxBase, wxSize, new_msg_id_pat);
results.new_msg_id_hits_count = nmi_hits.length;

// "msg_type" = 0a 08 6d 73 67 5f 74 79 70 65
var msg_type_pat = '0a 08 6d 73 67 5f 74 79 70 65';
var mt_hits = Memory.scanSync(wxBase, wxSize, msg_type_pat);
results.msg_type_hits_count = mt_hits.length;

send({t:'data', r: results});
"""

result_data = {}
done = __import__('threading').Event()

def on_message(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
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
done.wait(timeout=60)
sess.detach()

# ─── 解析 FileDescriptorProto ───────────────────────────────────────────────────
def parse_varint(data, pos):
    val = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        val |= (b & 0x7F) << shift; shift += 7
        if not (b & 0x80): break
    return val, pos

def decode_pb_full(data_bytes, indent=0, max_depth=3, limit=100):
    """解析 protobuf FileDescriptorProto"""
    results = []
    i = 0; count = 0
    while i < len(data_bytes) and count < limit:
        if data_bytes[i] == 0: break
        try:
            tag, i = parse_varint(data_bytes, i)
            w = tag & 7; f = tag >> 3
            if f == 0 or f > 10000: break
            if w == 0:
                v, i = parse_varint(data_bytes, i)
                results.append({'f':f,'t':'v','v':v})
                count += 1
            elif w == 2:
                ln, i = parse_varint(data_bytes, i)
                if ln > 100000 or i + ln > len(data_bytes): break
                pay = bytes(data_bytes[i:i+ln]); i += ln
                try:
                    s = pay.decode('utf-8')
                    results.append({'f':f,'t':'s','v':s,'raw':pay.hex()})
                except:
                    sub = decode_pb_full(pay, indent+1, max_depth, 20) if indent < max_depth else []
                    results.append({'f':f,'t':'b','len':ln,'hex':pay[:32].hex(),'sub':sub})
                count += 1
            elif w == 5: i += 4; count += 1
            elif w == 1: i += 8; count += 1
            else: break
        except: break
    return results

def print_pb(fields, indent=0):
    pfx = '  ' * indent
    for f in fields:
        if f['t'] == 's':
            print(f'{pfx}f{f["f"]} (str): {repr(f["v"][:80])}')
        elif f['t'] == 'v':
            print(f'{pfx}f{f["f"]} (int): {f["v"]}')
        elif f['t'] == 'b':
            sub = f.get('sub', [])
            print(f'{pfx}f{f["f"]} (bytes, {f["len"]}B): {f["hex"][:20]}...')
            if sub:
                print_pb(sub, indent+1)

print(f'\n[=== FileDescriptorProto 分析 ===]')

print(f'\n--- crtxcgi.proto 描述符 ({len(result_data.get("crtx_hits",[]))} 处) ---')
for i, hit in enumerate(result_data.get('crtx_hits', [])):
    bs = bytes(hit['data'])
    addr = hit['addr']
    # 找 crtxcgi.proto 在 bs 中的位置
    needle = b'crtxcgi.proto'
    pos = bs.find(needle)
    if pos < 0: continue
    # 尝试从前面几个字节找 FileDescriptorProto 开始
    print(f'\n  hit#{i} @{addr}:')
    # 在前 32 字节寻找 proto 起始标志: 0x0a 0x0e 63 72...
    # 0x0a = field 1 wire 2, 0x0e = len 14 = len("crtxcgi.proto")
    start_idx = max(0, pos - 4)
    for j in range(max(0, pos-16), pos+1):
        if j+1 < len(bs) and bs[j] == 0x0a and bs[j+1] == 0x0e:
            print(f'  Found FileDescriptorProto start at offset {j} from read start')
            fields = decode_pb_full(bs[j:j+2000])
            print_pb(fields[:50])
            break
    else:
        # 尝试直接解析从找到位置前几字节
        strs = []
        for m in re.finditer(rb'[\x20-\x7e]{4,}', bs[pos:pos+512]):
            strs.append(m.group().decode('ascii','ignore'))
        print(f'  Strings after: {" | ".join(strs[:8])}')

print(f'\n--- ftn_cgi.proto 描述符 ({len(result_data.get("ftn_hits",[]))} 处) ---')
for i, hit in enumerate(result_data.get('ftn_hits', [])[:3]):
    bs = bytes(hit['data'])
    addr = hit['addr']
    needle = b'ftn_cgi.proto'
    pos = bs.find(needle)
    if pos < 0: continue
    print(f'\n  hit#{i} @{addr}:')
    for j in range(max(0, pos-16), pos+1):
        if j+1 < len(bs) and bs[j] == 0x0a and bs[j+1] == 0x0d:  # 0x0d = 13 = len("ftn_cgi.proto")
            print(f'  FileDescriptorProto start at offset {j}')
            fields = decode_pb_full(bs[j:j+4000])
            print_pb(fields[:100])
            break
    else:
        strs = []
        for m in re.finditer(rb'[\x20-\x7e]{4,}', bs[pos:pos+512]):
            strs.append(m.group().decode('ascii','ignore'))
        print(f'  Strings: {" | ".join(strs[:8])}')

print(f'\n--- ForwardMessageReq 二进制描述符搜索 ({len(result_data.get("fwd_desc_hits",[]))} 处) ---')
for i, hit in enumerate(result_data.get('fwd_desc_hits', [])[:3]):
    bs = bytes(hit['data'])
    addr = hit['addr']
    print(f'\n  hit#{i} @{addr}:')
    # 尝试从头解析
    fields = decode_pb_full(bs)
    print_pb(fields[:30])

print(f'\n--- to_username 字段搜索 ({len(result_data.get("to_username_hits",[]))} 处) ---')
for h in result_data.get('to_username_hits', [])[:3]:
    bs = bytes(h['data'])
    addr = h['addr']
    strs = [m.group().decode('ascii','ignore') for m in re.finditer(rb'[\x20-\x7e]{4,}', bs)]
    print(f'  @{addr}: {" | ".join(strs[:6])}')
    # 解析 FieldDescriptorProto
    fields = decode_pb_full(bs)
    print_pb(fields[:10])

print(f'\n  msg_type_hits_count: {result_data.get("msg_type_hits_count")}')
print(f'  new_msg_id_hits_count: {result_data.get("new_msg_id_hits_count")}')
print(f'  conv_proto_hits_count: {result_data.get("conv_hits_count")}')
print(f'  from_username_hits: {len(result_data.get("from_username_hits",[]))}')

ts = int(time.time())
out = OUT_DIR / f'filedesc_{ts}.json'
# 保存二进制数据
save = {
    'crtx_proto_data': [[b for b in hit['data'][:2000]] for hit in result_data.get('crtx_hits',[])],
    'ftn_proto_data': [[b for b in hit['data'][:4000]] for hit in result_data.get('ftn_hits',[])],
    'fwd_desc_data': [[b for b in hit['data'][:1024]] for hit in result_data.get('fwd_desc_hits',[])],
}
out.write_text(json.dumps(save, ensure_ascii=False, indent=2), encoding='utf-8')
print(f'\n[+] 保存: {out}')
os._exit(0)
