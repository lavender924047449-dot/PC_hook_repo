"""列出主进程所有 .db 文件句柄（扩展扫描到 0x10000）"""
import sys, subprocess, frida
sys.stdout.reconfigure(line_buffering=True)

def get_main_pid():
    out = subprocess.run(["netstat","-ano"],capture_output=True,text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
print(f"PID = {pid}")
dev = frida.get_local_device()

JS = r"""
'use strict';
var ntdll = Process.getModuleByName('ntdll.dll');
var NtQO  = new NativeFunction(ntdll.getExportByName('NtQueryObject'),
                'int', ['pointer','int','pointer','uint','pointer']);
var result = {};
for (var h = 4; h <= 0x10000; h += 4) {
    var buf = Memory.alloc(2048); var rl = Memory.alloc(4);
    try {
        if (NtQO(ptr(h), 1, buf, 2048, rl) !== 0) continue;
        var nl = buf.readU16(); if (nl === 0 || nl > 1000) continue;
        var sp = buf.add(4).readPointer(); if (sp.isNull()) continue;
        var name = sp.readUtf16String(nl / 2);
        if (name && name.indexOf('.db') >= 0) result[h] = name;
    } catch(e) {}
}
send({handles: result});
"""

found = {}
def on_msg(msg, data):
    global found
    if msg.get("type") == "send":
        found = msg["payload"].get("handles", {})

sess = dev.attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()

import time; time.sleep(30)
print(f"\n找到 {len(found)} 个 .db 句柄:")
for h, name in sorted(found.items(), key=lambda x: int(x[0])):
    print(f"  h={h:6}  {name}")
