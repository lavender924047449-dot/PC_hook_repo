# disasm_caller.py — 用 Frida 反汇编 caller 地址上下文
# 目标：定位包含 RVA 0x3ebf6c 的函数入口 (55 8B EC / 53 8B DC 序言)
#       并 dump 该地址前后 128 字节反汇编
import frida, subprocess, sys, time
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

def get_pid():
    o = subprocess.run(['netstat','-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    raise RuntimeError('no :9882')

pid = get_pid()
print(f'PID={pid}')

# 目标 caller (需反汇编上下文)
TARGETS_RVA = [0x3ebf6c]

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
var TARGETS = %s;
var out = {base: base.toString(), targets: []};

TARGETS.forEach(function(rva){
    var addr = base.add(rva);
    var info = {rva: '0x'+rva.toString(16), abs: addr.toString()};

    // 1) 向后 128 字节反汇编（从命中点起）
    var forward = [];
    var cursor = addr;
    var end = addr.add(128);
    while (cursor.compare(end) < 0) {
        try {
            var ins = Instruction.parse(cursor);
            forward.push({a: cursor.toString(), m: ins.mnemonic, o: ins.opStr, s: ins.size});
            cursor = ins.next;
        } catch(e) { break; }
    }
    info.forward = forward;

    // 2) 向前扫最多 4096 字节找函数序言 (55 8B EC / 53 8B DC)
    //    直接读字节，用简易签名匹配
    var scanStart = addr.sub(4096);
    var bytes = new Uint8Array(scanStart.readByteArray(4096));
    var proBlocks = [];
    for (var i = 0; i < bytes.length - 3; i++) {
        // 常见 x86 函数序言
        var ok = false, tag = '';
        // 55 8B EC
        if (bytes[i]===0x55 && bytes[i+1]===0x8b && bytes[i+2]===0xec) { ok=true; tag='PUSH_EBP;MOV_EBP_ESP'; }
        // 53 8B DC (rare)
        else if (bytes[i]===0x53 && bytes[i+1]===0x8b && bytes[i+2]===0xdc) { ok=true; tag='PUSH_EBX;MOV_EBX_ESP'; }
        // 8B FF 55 8B EC (hotpatch)
        else if (bytes[i]===0x8b && bytes[i+1]===0xff && bytes[i+2]===0x55 && bytes[i+3]===0x8b && bytes[i+4]===0xec) { ok=true; tag='HOTPATCH_MOV_EDI_EDI'; }
        if (ok) {
            var aa = scanStart.add(i);
            proBlocks.push({offset_from_hit: i - 4096, addr: aa.toString(), rva: '0x'+(rva - (4096 - i)).toString(16), tag: tag});
        }
    }
    // 最近的（最大 offset_from_hit，即离 addr 最近的负值）
    info.prologues_nearby = proBlocks.slice(-15);

    // 3) 若找到最近序言，反汇编前 40 条指令
    if (proBlocks.length > 0) {
        var nearest = proBlocks[proBlocks.length - 1];
        var pa = ptr(nearest.addr);
        var lst = [];
        var pc = pa;
        for (var j = 0; j < 40; j++) {
            try {
                var ins = Instruction.parse(pc);
                lst.push({a: pc.toString(), m: ins.mnemonic, o: ins.opStr});
                pc = ins.next;
                if (pc.compare(addr.add(32)) > 0) break;
            } catch(e) { break; }
        }
        info.func_prologue_disasm = lst;
        info.nearest_prologue = nearest;
    }
    out.targets.push(info);
});

send({t:'done', data: out});
""" % str(TARGETS_RVA)

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
result = {}
def on_msg(m, d):
    if m.get('type')=='send':
        p=m['payload']
        if p.get('t')=='done':
            result['d'] = p['data']
    elif m.get('type')=='error':
        print('ERR:', m.get('description'))
sc.on('message', on_msg)
sc.load()
t0=time.time()
while 'd' not in result and time.time()-t0<10:
    time.sleep(0.1)

import json
if 'd' in result:
    for tgt in result['d']['targets']:
        print(f"\n===== RVA {tgt['rva']}  abs={tgt['abs']} =====")
        print(f"[最近的函数序言]")
        for pb in tgt.get('prologues_nearby', []):
            print(f"  off_from_hit={pb['offset_from_hit']:+5d}  addr={pb['addr']}  RVA={pb['rva']}  {pb['tag']}")
        near = tgt.get('nearest_prologue')
        if near:
            print(f"\n[函数入口 {near['addr']}  RVA={near['rva']} 反汇编]")
            for ins in tgt.get('func_prologue_disasm', []):
                marker = '  <-- caller ret' if int(ins['a'],16) == int(tgt['abs'],16) else ''
                print(f"  {ins['a']}  {ins['m']:8} {ins['o']}{marker}")
        print(f"\n[hit 之后 128 字节]")
        for ins in tgt.get('forward', []):
            print(f"  {ins['a']}  {ins['m']:8} {ins['o']}")
    # 存 JSON
    from pathlib import Path
    from datetime import datetime
    out=Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')/f"disasm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(result['d'], ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"\n[+] JSON saved: {out.name}")
else:
    print('[!] no result')
sc.unload(); sess.detach()
