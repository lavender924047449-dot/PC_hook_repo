"""
ipc_capture.py
—————————————————————————————————————————————————————
用 frida Python API（非命令行）在主进程中注入 ipc_socket_hook.js，
捕获 :9882/:50010 的 IPC 流量 N 秒后退出并保存结果。

用法：
  python scripts/wecom_re/ipc_capture.py [秒数=40]
"""
import sys, time, datetime, json
from pathlib import Path

ROOT   = Path(__file__).resolve().parent.parent.parent
SCRIPT = Path(__file__).resolve().parent / "ipc_socket_hook.js"
OUT_DIR = ROOT / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 40

import frida

# 找主进程（:9882 监听进程，通过 netstat + frida enumerate）
def find_wxwork_pid():
    # 用 netstat 找监听 9882 端口的 PID
    import subprocess, re
    try:
        out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
        for line in out.splitlines():
            if "9882" in line and "LISTENING" in line:
                m = re.search(r'\s+(\d+)\s*$', line.strip())
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    # 退回：找名字为 WXWork.exe 的第一个进程
    dev = frida.get_local_device()
    for p in dev.enumerate_processes():
        if p.name.lower() == "wxwork.exe":
            return p.pid
    raise RuntimeError("WXWork.exe not found")

pid = find_wxwork_pid()
print(f"[*] Attaching to WXWork.exe  PID={pid}")

dev = frida.get_local_device()
session  = dev.attach(pid)
js_code  = SCRIPT.read_text("utf-8")

messages = []

def on_message(msg, data):
    if msg.get("type") == "send":
        payload = msg.get("payload", "")
        messages.append({"t": datetime.datetime.now().isoformat(), "msg": payload})
        print(payload)
    elif msg.get("type") == "error":
        print(f"[frida ERROR] {msg.get('description', '')}  stack={msg.get('stack','')[:200]}")

script = session.create_script(js_code)
script.on("message", on_message)
script.load()

print(f"[*] Hook injected. Capturing {DURATION}s ...  请在企微中做操作（切换聊天、收发消息等）")
print(f"    按 Ctrl+C 提前结束")

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

# 保存结果
ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
out  = OUT_DIR / f"ipc_dump_{ts}.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for m in messages:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

script.unload()
session.detach()

print(f"\n[*] 捕获完成: {len(messages)} 条消息 → {out}")
