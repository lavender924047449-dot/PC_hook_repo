"""
ipc_client_capture.py
————————————————————————————————————————
注入所有 WXWork 子进程，捕获它们连接 :9882 / :50010 时发送的 IPC 数据。
（主进程 PID=28432 是服务端；其他 WXWork.exe / WXWorkWeb.exe 是客户端）

用法：
  C:\\Users\\LENOVO\\AppData\\Local\\Programs\\Python\\Python311\\python.exe ^
      scripts/wecom_re/ipc_client_capture.py [秒数=40]
  
运行期间在企微中做各种操作（发消息、切换聊天、打开联系人等）触发 IPC 调用。
"""
import sys, time, json
from datetime import datetime
from pathlib import Path

DURATION  = int(sys.argv[1]) if len(sys.argv) > 1 else 40
IPC_PORTS = [9882, 50010]
OUT_DIR   = Path(__file__).resolve().parent.parent.parent / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

import frida

JS_HOOK = r"""
'use strict';
var IPC_PORTS = [9882, 50010];
var DUMP_MAX = 512;

function dumpBytes(buf, maxLen) {
    var b = new Uint8Array(buf);
    var len = Math.min(b.length, maxLen);
    var rows = [];
    for (var r = 0; r < len; r += 16) {
        var end = Math.min(r + 16, len); var h = ''; var a = '';
        for (var i = r; i < end; i++) {
            h += ('0' + b[i].toString(16)).slice(-2) + ' ';
            a += (b[i] >= 0x20 && b[i] < 0x7f) ? String.fromCharCode(b[i]) : '.';
        }
        rows.push(('000' + r.toString(16)).slice(-4) + '  ' + h.padEnd(48) + ' |' + a + '|');
    }
    if (b.length > maxLen) rows.push('... (' + b.length + ' bytes total)');
    return rows.join('\n');
}

function portFromSA(ptr) {
    try {
        if (ptr.readU16() !== 2) return -1;
        var r = ptr.add(2).readU16();
        return ((r & 0xff) << 8) | (r >> 8);
    } catch(e) { return -1; }
}

function emit(s) {
    try { send({ pid: Process.id, msg: s }); } catch(_) {}
}

var sockPort = {};
var mod;
try { mod = Process.getModuleByName('ws2_32.dll'); }
catch(e) { emit('ws2_32 not loaded'); }

if (mod) {
    Interceptor.attach(mod.getExportByName('connect'), {
        onEnter: function(a) {
            var p = portFromSA(a[1]);
            if (IPC_PORTS.indexOf(p) >= 0) {
                sockPort[a[0].toInt32()] = p;
                emit('[CONNECT] sock=' + a[0].toInt32() + ' -> port=' + p);
            }
        }
    });

    Interceptor.attach(mod.getExportByName('send'), {
        onEnter: function(a) {
            var s = a[0].toInt32();
            if (!(s in sockPort)) return;
            var n = a[2].toInt32(); if (n <= 0) return;
            var d = a[1].readByteArray(Math.min(n, DUMP_MAX));
            emit('[SEND->port=' + sockPort[s] + '] sock=' + s + ' len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
        }
    });

    Interceptor.attach(mod.getExportByName('recv'), {
        onEnter: function(a) { this.a = a; },
        onLeave: function(ret) {
            var n = ret.toInt32(); if (n <= 0) return;
            var s = this.a[0].toInt32(); if (!(s in sockPort)) return;
            var d = this.a[1].readByteArray(Math.min(n, DUMP_MAX));
            emit('[RECV<-port=' + sockPort[s] + '] sock=' + s + ' len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
        }
    });

    Interceptor.attach(mod.getExportByName('closesocket'), {
        onEnter: function(a) {
            var s = a[0].toInt32();
            if (s in sockPort) { emit('[CLOSE] sock=' + s); delete sockPort[s]; }
        }
    });

    emit('[ipc_client_hook ready] pid=' + Process.id);
}
"""

# ── 找 :9882 监听的主进程 PID ─────────────────────────────────────────────────
import subprocess, re

def get_listen_pid(port=9882):
    out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
    for line in out.splitlines():
        if str(port) in line and "LISTENING" in line:
            m = re.search(r'\s+(\d+)\s*$', line.strip())
            if m:
                return int(m.group(1))
    return None

server_pid = get_listen_pid(9882)
print(f"[*] Server (main WXWork.exe) PID={server_pid}")

# ── 注入所有 WXWork 进程（除主进程外都是客户端）────────────────────────────────
dev = frida.get_local_device()
procs = dev.enumerate_processes()
targets = [(p.pid, p.name) for p in procs
           if 'wxwork' in p.name.lower() and p.pid != server_pid]
print(f"[*] Client targets ({len(targets)}): {targets}")

all_messages = []
sessions, scripts = [], []

def make_handler(pid, name):
    def on_msg(msg, data):
        if msg.get("type") == "send":
            payload = msg["payload"]
            entry = {
                "t":    datetime.now().isoformat(),
                "pid":  payload.get("pid", pid),
                "proc": name,
                "msg":  payload.get("msg", ""),
            }
            all_messages.append(entry)
            print(f"[{name}:{entry['pid']}] {entry['msg'][:100]}")
        elif msg.get("type") == "error":
            print(f"[ERR pid={pid}]", msg.get("description", "")[:200])
    return on_msg

for pid, name in targets:
    try:
        sess = dev.attach(pid)
        sc   = sess.create_script(JS_HOOK)
        sc.on("message", make_handler(pid, name))
        sc.load()
        sessions.append(sess)
        scripts.append(sc)
        print(f"  [+] injected pid={pid} {name}")
    except Exception as e:
        print(f"  [-] SKIP pid={pid} {name}: {e}")

print(f"\n[*] Capturing {DURATION}s — 请在企微中操作（发消息、切换聊天）...")
print("    Ctrl+C 可提前结束\n")

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

# ── 保存结果 ─────────────────────────────────────────────────────────────────
ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"ipc_client_{ts}.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for m in all_messages:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

for sc in scripts:
    try: sc.unload()
    except Exception: pass
for sess in sessions:
    try: sess.detach()
    except Exception: pass

# ── 打印简要统计 ──────────────────────────────────────────────────────────────
connect_msgs = [m for m in all_messages if "[CONNECT]" in m["msg"]]
send_msgs    = [m for m in all_messages if "[SEND->"  in m["msg"]]
recv_msgs    = [m for m in all_messages if "[RECV<-"  in m["msg"]]

print(f"\n[*] 完成: {len(all_messages)} 条消息 -> {out}")
print(f"    CONNECT={len(connect_msgs)}  SEND={len(send_msgs)}  RECV={len(recv_msgs)}")

if send_msgs:
    print("\n=== 首条 SEND payload ===")
    print(send_msgs[0]["msg"][:800])
