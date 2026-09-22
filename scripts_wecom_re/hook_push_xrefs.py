"""
hook_push_xrefs.py
Hook 3 个 PUSH xref 地址 + 附近的 CALL 指令
找 sqlite3_prepare_v2 调用点
"""
import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

OUT = Path(r'd:\Only internship outputs\Test-Voice\runtime\wecom_re')
OUT.mkdir(parents=True, exist_ok=True)

def get_main_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("企微未运行")

pid = get_main_pid()
print(f"[*] PID = {pid}")
dev = frida.get_local_device()

# Phase 1: 读取 PUSH 地址附近的字节，找 CALL 指令
JS_SCOUT = r"""
'use strict';
var addrs = [0x2e5fa2b, 0x1f18bb5, 0x8f7a748];
var result = [];

for (var i = 0; i < addrs.length; i++) {
    var p = ptr(addrs[i]);
    var info = {addr: p.toString(), bytes: [], calls: []};
    
    // 读取 60 字节
    try {
        var raw = new Uint8Array(p.readByteArray(60));
        for (var j = 0; j < raw.length; j++) {
            info.bytes.push(raw[j]);
        }
        // 查找 CALL 指令: E8 xx xx xx xx (相对 CALL)
        for (var j = 0; j < raw.length - 5; j++) {
            if (raw[j] === 0xE8) {
                // 计算目标地址 (32-bit signed relative)
                var rel = raw[j+1] | (raw[j+2]<<8) | (raw[j+3]<<16) | (raw[j+4]<<24);
                // 处理符号扩展
                if (rel > 0x7FFFFFFF) rel = rel - 0x100000000;
                var callAddr = addrs[i] + j + 5 + rel;
                info.calls.push({
                    offset: j,
                    callAddr: '0x' + (callAddr >>> 0).toString(16)
                });
            }
            // CALL reg: FF D0-D7
            if (raw[j] === 0xFF && raw[j+1] >= 0xD0 && raw[j+1] <= 0xD7) {
                info.calls.push({offset: j, callAddr: 'reg:' + raw[j+1].toString(16)});
            }
        }
    } catch(e) {
        info.err = e.message;
    }
    result.push(info);
}
send({t:'scout', data: result});
"""

events = []

def on_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    events.append(p)
    if p.get("t") == "scout":
        for item in p["data"]:
            addr = item["addr"]
            calls = item.get("calls", [])
            bytes_hex = " ".join(f"{b:02x}" for b in item.get("bytes", [])[:20])
            print(f"\n[Scout] addr={addr}")
            print(f"  bytes: {bytes_hex}")
            for c in calls[:5]:
                print(f"  CALL at +{c['offset']}: -> {c['callAddr']}")

sess = dev.attach(pid)
sc0 = sess.create_script(JS_SCOUT)
sc0.on("message", on_msg)
sc0.load()
time.sleep(5)
sc0.unload()

print("\n[*] scout done, starting hooks...")

# Phase 2: hook 这 3 个 PUSH 地址
# 在 onEnter 时读 ESP 以下字节，看 stack 状态
JS_HOOK = """
'use strict';
var PUSH_ADDRS = [0x2e5fa2b, 0x1f18bb5, 0x8f7a748];
var HIT = 0;

for (var i = 0; i < PUSH_ADDRS.length; i++) {
    (function(hookAddr) {
        try {
            Interceptor.attach(ptr(hookAddr), {
                onEnter: function(args) {
                    if (HIT++ > 500) return;
                    
                    // 读 PUSH 指令后面 4 字节 (imm32 = string VA)
                    var instrBytes = [];
                    try {
                        var raw = new Uint8Array(ptr(hookAddr).readByteArray(5));
                        for (var j = 0; j < 5; j++) instrBytes.push(raw[j]);
                    } catch(e) {}
                    
                    // 读 ESP 上方 16 字节 (stack frame 内容)
                    var stackSnap = [];
                    var esp = this.context.esp;
                    try {
                        var raw2 = new Uint8Array(esp.readByteArray(32));
                        for (var j = 0; j < 32; j++) stackSnap.push(raw2[j]);
                    } catch(e) {}
                    
                    // 尝试读 SQL 字符串 (如果 args[0] 是指针)
                    var sql = '';
                    try { sql = args[1].readCString(200); } catch(e) {}
                    if (!sql) { try { sql = args[0].readCString(200); } catch(e) {} }
                    
                    send({t:'hit', hookAddr:hookAddr.toString(16), 
                          instr:instrBytes, stack:stackSnap,
                          sql:sql, tid:this.threadId,
                          ret:this.returnAddress.toString()});
                }
            });
            send({t:'hooked', addr:hookAddr.toString(16)});
        } catch(e) {
            send({t:'hook_err', addr:hookAddr.toString(16), e:e.message});
        }
    })(PUSH_ADDRS[i]);
}
"""

hits = []

def on_hook_msg(msg, data):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    events.append(p)
    t = p.get("t","")
    if t == "hooked":
        print(f"  [hooked] addr=0x{p['addr']}")
    elif t == "hook_err":
        print(f"  [err] addr=0x{p['addr']}: {p.get('e','')}")
    elif t == "hit":
        hits.append(p)
        instr = " ".join(f"{b:02x}" for b in p.get("instr",[]))
        sql = p.get("sql","")
        print(f"\n[HIT] @0x{p['hookAddr']} tid={p['tid']} ret={p['ret']}")
        print(f"  instr: {instr}")
        print(f"  sql: {sql[:120]!r}")

sc1 = sess.create_script(JS_HOOK)
sc1.on("message", on_hook_msg)
sc1.load()

print("\n>>> 请立刻执行: 右键消息 -> 转发 -> 选人 -> 发送 <<<")
OUT.joinpath("push_hook_ready.flag").write_text("ready")
print("[*] 等待 90s...")

try:
    time.sleep(90)
except KeyboardInterrupt:
    pass

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_f = OUT / f"push_hook_{ts}.json"
out_f.write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\n[*] 完成: {len(hits)} 次命中 -> {out_f}")
