# probe_wxwork.py — 检查当前企微主进程是否可 attach + hook 探测
import frida, subprocess, sys, time

sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)

def get_main_pid():
    o = subprocess.run(['netstat', '-ano'], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ':9882' in l and 'LISTENING' in l:
            return int(l.strip().split()[-1])
    return None

pid = get_main_pid()
if not pid:
    print('[FAIL] 未找到 :9882 LISTENING 的企微主进程，请确认已登录')
    sys.exit(1)

print(f'[OK] 主进程 PID={pid} (:9882)')

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var base = wx.base;
var hits = { c390: 0, c449: 0, wbwc: 0 };

function readTag4(beginV) {
    try {
        var metaPtr = ptr(beginV).add(52).readU32() >>> 0;
        var m = new Uint8Array(ptr(metaPtr).readByteArray(256));
        for (var i = 0; i < m.length - 3; i++) {
            if (m[i]===0xd0 && m[i+1]===0x07 && m[i+2]===0x00 && m[i+3]===0x02) {
                if (i + 28 <= m.length) {
                    return String.fromCharCode(m[i+24], m[i+25], m[i+26], m[i+27]);
                }
            }
        }
    } catch(e) {}
    return null;
}

Interceptor.attach(base.add(0x390ce0), {
    onEnter: function(args) {
        hits.c390++;
        var tag = readTag4(args[1].toInt32() >>> 0);
        if (tag === 'WbWC' || tag === 'b0jW') {
            hits.wbwc++;
            send({t:'fwd', tag: tag, n: hits.wbwc});
        }
    }
});
Interceptor.attach(base.add(0x449fa7), {
    onEnter: function(args) { hits.c449++; }
});

recv('stat', function(_) { send({t:'stat', hits: hits, base: base.toString()}); });
send({t:'ready', base: base.toString()});
"""

stat = {}
ready = [False]

def on_msg(msg, data):
    if msg.get('type') == 'error':
        print(f'[ERR] {msg.get("description","")[:200]}')
        return
    if msg.get('type') != 'send':
        return
    p = msg['payload']
    if p.get('t') == 'ready':
        ready[0] = True
        print(f'[OK] Frida attach 成功, wxBase={p["base"]}')
    elif p.get('t') == 'fwd':
        print(f'  ⚡ 转发探测: {p["tag"]} #{p["n"]}')
    elif p.get('t') == 'stat':
        stat.update(p.get('hits', {}))

try:
    sess = frida.get_local_device().attach(pid)
except Exception as e:
    print(f'[FAIL] Frida attach 失败: {e}')
    sys.exit(1)

sc = sess.create_script(JS)
sc.on('message', on_msg)
sc.load()
time.sleep(0.5)
if not ready[0]:
    print('[FAIL] Hook 脚本未就绪')
    sys.exit(1)

print('[*] 监听 15s（可做任意操作或转发 1 次验证）...')
time.sleep(15)
sc.post({'type': 'stat'})
time.sleep(0.5)

print(f'[STAT] 0x390CE0 命中={stat.get("c390",0)}  WbWC/b0jW={stat.get("wbwc",0)}  0x449FA7={stat.get("c449",0)}')
if stat.get('c390', 0) > 0:
    print('[OK] Hook 点正常响应，可以开始 A/B 捕获')
else:
    print('[WARN] 15s 内无 CGI 活动（可能正常），转发 1 次可进一步确认')

sc.unload()
sess.detach()
print('[OK] 已 detach，企微可正常使用')
