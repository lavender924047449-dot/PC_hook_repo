"""
forward_msg_trace.py
精准监控 message.db NtWriteFile + FUZZY backtrace
只附加主进程，只 hook 11 个精确 handle，安全无崩溃风险
"""
import sys, time, json, frida
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
pid = 27304  # 主进程

JS = """
"use strict";
// message.db 相关 handle (h=3452,3472,3476,5484,5488 + lookup/index)
var DB_SET = {};
[3452,3472,3476,5484,5488,3456,3460,3652,3656,3744,3748].forEach(function(h){DB_SET[h]=1;});

var ntdll = Process.getModuleByName("ntdll.dll");
var NtWriteFile = ntdll.getExportByName("NtWriteFile");
var HIT = 0;

Interceptor.attach(NtWriteFile, {
    onEnter: function(args){
        var h = args[0].toUInt32();
        if (!DB_SET[h]) return;
        if (HIT++ > 200) return;
        var bt = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,8)
                       .map(function(a){ return a.toString(); });
        var preview = "";
        try {
            var len = Math.min(args[6].toUInt32(), 128);
            if (len > 0) {
                var bytes = new Uint8Array(args[5].readByteArray(len));
                var asc = Array.from(bytes).map(function(b){
                    return (b>=32 && b<127) ? String.fromCharCode(b) : ".";
                }).join("");
                preview = asc.substring(0, 64);
            }
        } catch(e){}
        send({t:"hit", h:h, tid:this.threadId, bt:bt, p:preview});
    }
});
send({t:"ready"});
"""

events = []
hit_count = 0

def on_msg(msg, data):
    global hit_count
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    events.append(p)
    t = p.get("t","")
    if t == "ready":
        print("[READY] message.db NtWriteFile hook 已就绪!")
        print(">>> 请立刻执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
        OUT.joinpath("forward_hook_ready.flag").write_text("ready")
    elif t == "hit":
        hit_count += 1
        h = p.get("h")
        tid = p.get("tid")
        bt = p.get("bt", [])
        pv = p.get("p", "")
        print(f"\n[HIT #{hit_count}] handle={h} tid={tid}")
        for b in bt:
            print(f"  {b}")
        if pv:
            print(f"  data: {pv!r}")

dev = frida.get_local_device()
sess = dev.attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
print("[*] Hook 加载完成，等待 90s...")

try:
    time.sleep(90)
except KeyboardInterrupt:
    print("[*] Ctrl+C")

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT / f"forward_msg_trace_{ts}.json"
out.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"[*] 完成: {hit_count} 次 DB 写命中 -> {out}")
