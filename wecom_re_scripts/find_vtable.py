# find_vtable.py: 找 SyncFWMessageTask 的 vtable 和 Execute/Begin 函数入口
# 通过 RTTI -> TypeDescriptor -> CompleteObjectLocator -> vtable

import frida, subprocess, sys, os, time, threading, json, re, struct
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

# 已知：
# SyncFWMessageTask TypeDescriptor 在 0xf0c38c4
# 搜索 CompleteObjectLocator 中对 0xf0c38c4 的引用
TD_ADDR = 0xf0c38c4

# "[SyncFWMessageTask] begin" 字符串在 0xb777e0c
# 引用点在 0x94724a3，附近有 PUSH 0xb777e0c 在 0x94724a2
# 扫描函数入口（向上找 55 8b ec 或其他 prologue）
BEGIN_REF = 0x9472482  # 附近的 PUSH 0x68 指令

JS = r"""
'use strict';
var wx = Process.enumerateModules().find(function(m){ return m.name.toLowerCase() === 'wxwork.exe'; });
var wxBase = wx.base;
var wxSize = wx.size;
var results = {};

// 1. 找 CompleteObjectLocator 引用 TypeDescriptor 0xf0c38c4
// c4 38 c3 0f = LE of 0x0fc338c4 (but TypeDescriptor is at 0xf0c38c4 = 0x0f0c38c4)
var td_le_str = 'c4 38 0c f0';  // LE of 0xf0c38c4
var col_hits = Memory.scanSync(wxBase, wxSize, td_le_str);
results.col_hits = {count: col_hits.length, entries: col_hits.slice(0,5).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(12).readByteArray(64))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 2. 扫描 SyncFWMessageTask 函数入口：向前扫描 0x94724a2 找 PUSH EBP
// 函数 prologue 通常是: 55 8b ec (PUSH EBP; MOV EBP, ESP) 或 8b ff (MOV EDI, EDI)
var begin_code = [];
try{ begin_code = Array.from(new Uint8Array(ptr(""" + hex(BEGIN_REF - 200) + """).readByteArray(300))); } catch(e){}
results.begin_code = {data: begin_code, base: """ + hex(BEGIN_REF - 200) + """};

// 3. 找 SyncFWMessageTask 的 Execute 方法
// 搜索 SyncFWMessageTask 在函数签名中
// 实际上 ServiceTask::Execute 是虚方法，在 vtable 中

// 4. 扫描前后 4096 字节的代码，找其他 SyncFWMessageTask 日志字符串引用
var all_syncfw = Memory.scanSync(wxBase, wxSize, '53 79 6e 63 46 57 4d 65 73 73 61 67 65 54 61 73 6b');
results.syncfw_all = {count: all_syncfw.length, entries: all_syncfw.slice(0,10).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(16).readByteArray(128))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 5. 找 "SyncFWMessageTask" 引用的代码地址（通过字符串引用）
var str_addr = 0xb777e0c;  // "[SyncFWMessageTask] begin"
// 找所有 PUSH str_addr 模式（68 0c 7e 77 0b）
var push_str_pattern = '68 0c 7e 77 0b';
var push_hits = Memory.scanSync(wxBase, wxSize, push_str_pattern);
results.push_begin_str = {count: push_hits.length, entries: push_hits.slice(0,5).map(function(h){
    // 读函数附近的代码（200字节）
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(200).readByteArray(400))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

// 6. 找 "sync_fw_message_task" 相关字符串附近的代码
// 在 0xb777e0d: "SyncFWMessageTask" string table
// 找所有引用到 0xb777e44 ("kHasClickMigrateChatRecordViewKey") 的指令
var migrate_str = 0xb777e44;
var push_migrate = ('68 ' + [migrate_str & 0xff, (migrate_str>>8)&0xff, (migrate_str>>16)&0xff, (migrate_str>>24)&0xff].map(function(b){ return ('0'+b.toString(16)).slice(-2); }).join(' ')).replace(/ /g, ' ');
var migrate_hits = Memory.scanSync(wxBase, wxSize, push_migrate);
results.push_migrate = {count: migrate_hits.length, entries: migrate_hits.slice(0,3).map(function(h){
    var data = [];
    try{ data = Array.from(new Uint8Array(h.address.sub(300).readByteArray(600))); } catch(e){}
    return {addr: h.address.toString(), data: data};
})};

send({t:'data', r: results});
"""

result_data = {}
done = threading.Event()

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
done.wait(timeout=30)
sess.detach()

# ── 分析 ──────────────────────────────────────────────────────────────────────
def find_function_entry(code_bytes, hit_offset, base_addr):
    """从 hit_offset 向前找函数 prologue (55 8b ec 或 8b ff 55 8b ec)"""
    for i in range(hit_offset, max(-1, hit_offset - 200), -1):
        if i >= 0 and code_bytes[i] == 0x55:  # PUSH EBP
            if i+2 < len(code_bytes) and code_bytes[i+1] == 0x8b and code_bytes[i+2] == 0xec:
                return base_addr + i
        if i >= 1 and code_bytes[i] == 0x8b and code_bytes[i-1] == 0xff:  # MOV EDI, EDI
            if i+1 < len(code_bytes) and code_bytes[i+1] == 0x55:  # PUSH EBP
                return base_addr + i - 1
    return None

print('\n[=== SyncFWMessageTask vtable 分析 ===]')

# 1. CompleteObjectLocator 引用
col_info = result_data.get('col_hits', {})
print(f'\nCompleteObjectLocator 引用 TypeDescriptor: {col_info.get("count",0)} 处')
for entry in col_info.get('entries', [])[:3]:
    addr = entry['addr']
    bs = bytes(entry.get('data', []))
    hex_str = ' '.join(f'{b:02x}' for b in bs[:32])
    print(f'  COL@{addr}: {hex_str}')
    # 尝试解析 COL 结构
    # COL: [signature=0][offset][cdOffset][TypeDesc ptr][ClassHier ptr]
    # 引用 TypeDescriptor 的地方就是 COL+12 (第4个uint32)
    # COL 基址 = ref_addr - 12
    col_addr = int(addr, 16) - 12
    print(f'    → COL base = 0x{col_addr:08x}')
    # vtable pointer to COL = COL_addr (the word BEFORE vtable[0])
    # vtable = COL + 20 bytes? No: vtable[-1] = COL_addr
    # So vtable entry = *search* for COL_addr in memory
    print(f'    → 搜索 vtable[-1] = 0x{col_addr:08x}')

# 2. begin 代码分析
begin_code = bytes(result_data.get('begin_code', {}).get('data', []))
base = result_data.get('begin_code', {}).get('base', 0)
if begin_code:
    print(f'\n从 0x{base:08x} 读取 {len(begin_code)} 字节代码')
    # 找函数入口
    hit_off = BEGIN_REF - base  # 偏移量
    entry = find_function_entry(list(begin_code), hit_off, base)
    if entry:
        print(f'  SyncFWMessageTask::Begin 函数入口可能在: 0x{entry:08x} (RVA=0x{entry-0x2d0000:x})')
    else:
        print(f'  未找到 55 8b ec prologue')
    
    # 打印关键范围的代码 hex
    print(f'\n  代码 hex (从入口附近):')
    start = max(0, hit_off - 80)
    end = min(len(begin_code), hit_off + 40)
    hex_out = ''
    for i, b in enumerate(begin_code[start:end]):
        hex_out += f'{b:02x} '
        if (i+1) % 16 == 0: hex_out += '\n    '
    print(f'  {hex_out}')

# 3. push_begin_str 分析（更完整）
print(f'\nPUSH [SyncFWMessageTask begin] 指令: {result_data.get("push_begin_str",{}).get("count",0)} 处')
for entry in result_data.get('push_begin_str', {}).get('entries', [])[:2]:
    addr = entry['addr']
    code = bytes(entry.get('data', []))
    base_code = int(addr, 16) - 200
    
    # 找函数入口
    push_off = 200  # 相对于 base_code 的偏移
    entry_addr = find_function_entry(list(code), push_off, base_code)
    if entry_addr:
        print(f'  PUSH@{addr} → 函数入口: 0x{entry_addr:08x} (RVA=0x{entry_addr-0x2d0000:x})')
        # 打印入口后的 32 字节
        off_in_buf = entry_addr - base_code
        if 0 <= off_in_buf < len(code) - 32:
            hex_entry = ' '.join(f'{b:02x}' for b in code[off_in_buf:off_in_buf+32])
            print(f'    Entry bytes: {hex_entry}')
    else:
        print(f'  PUSH@{addr} - 未找到函数入口')
    
    # 找参数（THIS 调用约定：ECX = this）
    # 在函数入口前，扫描 CALL 指令
    print(f'  扫描 base_code 0x{base_code:08x} 的前 200 字节:')
    hex_str = ' '.join(f'{b:02x}' for b in code[:50])
    print(f'    {hex_str}')

# 4. push_migrate 分析
print(f'\nPUSH kHasClickMigrateChatRecordViewKey: {result_data.get("push_migrate",{}).get("count",0)} 处')
for entry in result_data.get('push_migrate', {}).get('entries', [])[:2]:
    addr = entry['addr']
    code = bytes(entry.get('data', []))
    base_code = int(addr, 16) - 300
    
    entry_addr = find_function_entry(list(code), 300, base_code)
    if entry_addr:
        print(f'  → 函数入口: 0x{entry_addr:08x} (RVA=0x{entry_addr-0x2d0000:x})')

# 5. SyncFWMessageTask 所有字符串引用
print(f'\nSyncFWMessageTask 相关字符串: {result_data.get("syncfw_all",{}).get("count",0)} 处')
for entry in result_data.get('syncfw_all', {}).get('entries', [])[:5]:
    addr = entry['addr']
    bs = bytes(entry.get('data', []))
    strs = [(m.start(), m.group().decode('ascii','ignore')) for m in re.finditer(rb'[\x20-\x7e]{5,}', bs)]
    print(f'  @{addr}:')
    for off, s in strs[:4]:
        print(f'    +{off}: {s[:80]}')

os._exit(0)
