# disasm_cgi_fn.py -- 反汇编 CGI 函数开头 320 字节，理解参数结构
import frida, subprocess, sys, os, threading
sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

def get_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ':9882' in line and 'LISTENING' in line:
            return int(line.strip().split()[-1])

pid = get_pid()
print(f'[+] PID = {pid}', flush=True)

done = threading.Event()
result = {}

def on_msg(msg, data):
    if msg.get('type') == 'send':
        result.update(msg['payload'])
    elif msg.get('type') == 'error':
        print('ERR:', msg['description'][:300], flush=True)
    done.set()

sess = frida.get_local_device().attach(pid)
JS = r"""
'use strict';
var wxBase = Process.enumerateModules().find(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
}).base;

var fnStart = wxBase.add(0x390A30);
var hookMid = wxBase.add(0x390B39);
var spanSize = hookMid.sub(fnStart).toUInt32() + 20;  // 265 + 20 = 285 bytes

// 反汇编
var insns = [];
var cur = fnStart;
var count = 0;
while (cur.compare(hookMid.add(20)) < 0 && count < 200) {
    try {
        var insn = Instruction.parse(cur);
        var rva = cur.sub(wxBase).toUInt32();
        var isMid = (rva === 0x390B39);
        insns.push({
            rva: rva,
            abs: cur.toString(),
            asm: insn.toString(),
            size: insn.size,
            mid: isMid
        });
        cur = cur.add(insn.size);
        count++;
    } catch(e) {
        insns.push({rva: cur.sub(wxBase).toUInt32(), asm: 'ERR:'+e.message, size: 1});
        cur = cur.add(1);
        count++;
    }
}
send({insns: insns, wxBase: wxBase.toString()});
"""
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
done.wait(20)

print(f"wxBase: {result.get('wxBase')}", flush=True)
print(f"\n=== 反汇编 RVA 0x390A30 (CGI function prologue) ===", flush=True)
for insn in result.get('insns', []):
    marker = ' <<<< HOOK POINT' if insn.get('mid') else ''
    print(f"  0x{insn['rva']:08x}:  {insn['asm']}{marker}", flush=True)

sess.detach()
os._exit(0)
