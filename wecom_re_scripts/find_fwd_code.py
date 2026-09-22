# find_fwd_code.py -- 通过 log 字符串引用反向找到 ForwardMessageToSelectConversation 代码地址
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
var wxBase = null;
var wxSize = 0;
var mods = Process.enumerateModules();
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        wxBase = mods[i].base;
        wxSize = mods[i].size;
        break;
    }
}

function toHex4(val) {
    return ('00000000' + val.toString(16)).slice(-8);
}

function searchPush(strAbsAddr) {
    // 搜索 PUSH imm32 = 68 [4 bytes little-endian]
    var lo = strAbsAddr & 0xFF;
    var b1 = (strAbsAddr >> 8) & 0xFF;
    var b2 = (strAbsAddr >> 16) & 0xFF;
    var b3 = (strAbsAddr >> 24) & 0xFF;
    var pat = '68 ' +
        ('0'+lo.toString(16)).slice(-2) + ' ' +
        ('0'+b1.toString(16)).slice(-2) + ' ' +
        ('0'+b2.toString(16)).slice(-2) + ' ' +
        ('0'+b3.toString(16)).slice(-2);
    var found = [];
    try {
        var res = Memory.scanSync(wxBase, wxSize, pat);
        for (var k = 0; k < Math.min(res.length, 5); k++) {
            var rva = res[k].address.sub(wxBase).toUInt32();
            // 读取前后上下文 (前 16 + 后 32 字节)
            var ctx = '';
            try {
                var ctxBuf = res[k].address.sub(16).readByteArray(64);
                var ctxArr = new Uint8Array(ctxBuf);
                var arr = [];
                for (var j = 0; j < ctxArr.length; j++) {
                    arr.push(('0' + ctxArr[j].toString(16)).slice(-2));
                }
                ctx = arr.join(' ');
            } catch(e) {}
            found.push({rva: rva, ctx: ctx});
        }
    } catch(e) { found.push({rva: -1, err: e.message}); }
    return found;
}

// 目标 log 字符串地址（RVA → 绝对地址）
var strRVAs = [
    0x0b02f489,  // "ForwardMessageToSelectConversation] continue"
    0x0b02f4d5,  // "ForwardMessageToSelectConversation] err_code"
    0x0b02f529,  // "ForwardMessageToSelectConversation] start disable"
    0x0b02f5c9,  // "ForwardMessageToSelectConversationInternal]. hwnd"
    0x0ab3374a,  // "ForwardMessageToModelMessage failed, content_type"
    0x0afbca11,  // "ForwardMessageToModelMessage failed, msg_type"
    0x0b34cc92,  // "ForwardMessageToWeChat start."
];

var out = {};
for (var si = 0; si < strRVAs.length; si++) {
    var strAbs = wxBase.add(strRVAs[si]).toUInt32();
    var refs = searchPush(strAbs);
    out[toHex4(strRVAs[si])] = refs;
}
send({results: out, wxBase: wxBase.toString()});
"""
sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
done.wait(60)

print(f"wxBase: {result.get('wxBase')}", flush=True)
for str_rva, refs in result.get('results', {}).items():
    print(f'\n=== log string RVA 0x{str_rva} ===', flush=True)
    for ref in refs:
        if 'err' in ref:
            print(f'  ERR: {ref["err"]}', flush=True)
        else:
            rva = ref['rva']
            print(f'  PUSH at RVA 0x{rva:08x}', flush=True)
            # 上下文 hex dump（前16字节是上下文）
            ctx = ref.get('ctx', '')
            if ctx:
                bs = bytes.fromhex(ctx.replace(' ',''))
                rows = [bs[i:i+16] for i in range(0, len(bs), 16)]
                for j, row in enumerate(rows):
                    hex_part = ' '.join(f'{b:02x}' for b in row)
                    asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
                    base_off = (j - 1) * 16  # offset -16 = before PUSH
                    print(f'    {base_off:+5d}: {hex_part:<47}  {asc_part}', flush=True)

sess.detach()
os._exit(0)
