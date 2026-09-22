"""
ipc_qt_capture.py
————————————————————————————————————————
专门捕获 IPC-Qt 管道流量。
运行本脚本后：
  1. 在企微中手动触发【转发】操作（右键消息 → 转发），或
  2. 等脚本自动运行 spike_rightclick_autotest.py

捕获到的 JSON 命令将写入 runtime/wecom_re/ipc_qt_*.jsonl

用法：
  python scripts/wecom_re/ipc_qt_capture.py [秒数=90]
"""
import sys, time, json, subprocess, re, threading
from datetime import datetime
from pathlib import Path

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 90
OUT_DIR  = Path(__file__).resolve().parent.parent.parent / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ROOT = Path(__file__).resolve().parent.parent.parent

import frida

SCAN_JS = r"""
'use strict';
var ntdll = Process.getModuleByName('ntdll.dll');
var NtQO = new NativeFunction(ntdll.getExportByName('NtQueryObject'),
    'int', ['pointer', 'int', 'pointer', 'uint', 'pointer']);
var result = {};
for (var h = 4; h <= 0x8000; h += 4) {
    var buf = Memory.alloc(2048); var rl = Memory.alloc(4);
    if (NtQO(ptr(h), 1, buf, 2048, rl) !== 0) continue;
    var nl = buf.readU16(); if (nl === 0) continue;
    var sp = buf.add(4).readPointer(); if (sp.isNull()) continue;
    try {
        var name = sp.readUtf16String(nl / 2);
        if (name && (name.indexOf('WXWork.IPC-Qt') >= 0 || name.indexOf('WXFlutter.IPC') >= 0)) {
            result[h] = name;
        }
    } catch(e) {}
}
send({ type: 'scan', handles: result });
"""

HOOK_JS = r"""
'use strict';
var PIPE_HANDLES = [HANDLES_PLACEHOLDER];
var HANDLE_NAMES = NAMES_PLACEHOLDER;
var DUMP_MAX = 2048;

function emit(s) { try { send({ type: 'data', msg: s }); } catch(_) {} }

function dumpAndParse(buf, maxLen, prefix) {
    var b = new Uint8Array(buf);
    var len = Math.min(b.length, maxLen);
    // 尝试解析 JSON（跳过前 5 字节帧头）
    var jsonStr = '';
    if (len > 5) {
        try {
            // 帧头: [4B LE len][1B flags][JSON...]
            var jsonBytes = b.slice(5, len);
            for (var i = 0; i < jsonBytes.length; i++)
                jsonStr += String.fromCharCode(jsonBytes[i]);
        } catch(e) {}
    }
    var rows = [];
    for (var r = 0; r < len; r += 16) {
        var end = Math.min(r + 16, len); var h = ''; var a = '';
        for (var i = r; i < end; i++) {
            h += ('0' + b[i].toString(16)).slice(-2) + ' ';
            a += (b[i] >= 0x20 && b[i] < 0x7f) ? String.fromCharCode(b[i]) : '.';
        }
        rows.push(('000' + r.toString(16)).slice(-4) + '  ' + h.padEnd(48) + ' |' + a + '|');
    }
    if (b.length > maxLen) rows.push('... (' + b.length + ' bytes)');
    emit(prefix + '\nhex:\n' + rows.join('\n') + '\njson_payload: ' + jsonStr);
}

var ntdll = Process.getModuleByName('ntdll.dll');
var k32   = Process.getModuleByName('kernel32.dll');

Interceptor.attach(ntdll.findExportByName('NtWriteFile'), {
    onEnter: function(a) {
        var h = a[0].toInt32();
        if (PIPE_HANDLES.indexOf(h) < 0) return;
        var n = a[6].toInt32(); if (n <= 0 || n > 1048576) return;
        try {
            var d = a[5].readByteArray(Math.min(n, DUMP_MAX));
            dumpAndParse(d, DUMP_MAX, '[NtWrite pipe=' + (HANDLE_NAMES[h]||h) + ' len=' + n + ']');
        } catch(e) {}
    }
});

Interceptor.attach(ntdll.findExportByName('NtReadFile'), {
    onEnter: function(a) {
        this.h = PIPE_HANDLES.indexOf(a[0].toInt32()) >= 0 ? a[0].toInt32() : 0;
        this.buf = a[5]; this.iosb = a[4];
    },
    onLeave: function(ret) {
        if (!this.h) return;
        if (ret.toInt32() !== 0 && ret.toInt32() !== 0x103) return;
        try {
            var n = this.iosb.add(Process.pointerSize).readU32();
            if (n <= 0 || n > 1048576) return;
            var d = this.buf.readByteArray(Math.min(n, DUMP_MAX));
            dumpAndParse(d, DUMP_MAX, '[NtRead  pipe=' + (HANDLE_NAMES[this.h]||this.h) + ' len=' + n + ']');
        } catch(e) {}
    }
});

Interceptor.attach(k32.findExportByName('WriteFile'), {
    onEnter: function(a) {
        var h = a[0].toInt32();
        if (PIPE_HANDLES.indexOf(h) < 0) return;
        var n = a[2].toInt32(); if (n <= 0) return;
        try {
            var d = a[1].readByteArray(Math.min(n, DUMP_MAX));
            dumpAndParse(d, DUMP_MAX, '[WF-Write pipe=' + (HANDLE_NAMES[h]||h) + ' len=' + n + ']');
        } catch(e) {}
    }
});

Interceptor.attach(k32.findExportByName('ReadFile'), {
    onEnter: function(a) {
        this.h = PIPE_HANDLES.indexOf(a[0].toInt32()) >= 0 ? a[0].toInt32() : 0;
        this.a = a;
    },
    onLeave: function(ret) {
        if (!this.h || !ret.toInt32()) return;
        try {
            var n = this.a[3].isNull() ? 0 : this.a[3].readU32();
            if (n <= 0) return;
            var d = this.a[1].readByteArray(Math.min(n, DUMP_MAX));
            dumpAndParse(d, DUMP_MAX, '[WF-Read pipe=' + (HANDLE_NAMES[this.h]||this.h) + ' len=' + n + ']');
        } catch(e) {}
    }
});

emit('[ipc_qt_hook ready] pid=' + Process.id + ' handles=' + PIPE_HANDLES.join(','));
"""

def get_listen_pid(port=9882):
    out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
    for line in out.splitlines():
        if str(port) in line and "LISTENING" in line:
            m = re.search(r'\s+(\d+)\s*$', line.strip())
            if m: return int(m.group(1))
    return None

main_pid = get_listen_pid(9882)
print(f"[*] Main WXWork PID = {main_pid}")

dev  = frida.get_local_device()
sess = dev.attach(main_pid)

# ── 扫描管道 handle ───────────────────────────────────────────────────────────
print("[*] Scanning IPC-Qt handles...")
pipe_handles = {}
scan_done = threading.Event()

def on_scan(msg, data):
    if msg.get("type") == "send":
        pl = msg.get("payload", {})
        if pl.get("type") == "scan":
            for k, v in pl.get("handles", {}).items():
                label = v.split("NamedPipe\\")[-1][:40]
                pipe_handles[int(k)] = label
            scan_done.set()

sc_scan = sess.create_script(SCAN_JS)
sc_scan.on("message", on_scan)
sc_scan.load()
scan_done.wait(timeout=15)
sc_scan.unload()

if not pipe_handles:
    print("[!] No IPC-Qt handles found. Trying fallback...")
    pipe_handles = {5996: "IPC-Qt"}
else:
    print(f"[*] Found handles: {pipe_handles}")

# ── 注入 hook ─────────────────────────────────────────────────────────────────
handle_list = ", ".join(str(h) for h in pipe_handles.keys())
handle_names = "{" + ", ".join(f"{h}: '{n}'" for h, n in pipe_handles.items()) + "}"
hook_js = HOOK_JS.replace("HANDLES_PLACEHOLDER", handle_list).replace("NAMES_PLACEHOLDER", handle_names)

all_messages = []
data_messages = []

def on_hook(msg, data):
    if msg.get("type") == "send":
        pl = msg.get("payload", {})
        if pl.get("type") == "data":
            txt = pl.get("msg", "")
            entry = {"t": datetime.now().isoformat(), "pid": main_pid, "msg": txt}
            all_messages.append(entry)
            data_messages.append(entry)
            print(f"  [IPC-Qt] {txt[:150]}")
        elif pl.get("type") == "ready":
            print("  [hook] ready")
    elif msg.get("type") == "error":
        print(f"  [ERR] {msg.get('description','')[:200]}")

sc_hook = sess.create_script(hook_js)
sc_hook.on("message", on_hook)
sc_hook.load()

print(f"\n[*] IPC-Qt hook 已注入。捕获 {DURATION}s")
print("    请在企微中执行以下操作之一：")
print("    A) 手动右键消息 → 转发")
print("    B) 切换聊天列表")
print("    C) 等待自动化脚本触发（见下）")
print()

# ── 20s 后自动运行验收脚本触发 IPC-Qt 流量 ───────────────────────────────────
def run_spike_after_delay(delay_s):
    time.sleep(delay_s)
    print(f"\n  [auto] 启动 spike_rightclick_autotest.py 以触发 IPC 流量...")
    spike = ROOT / "spikes" / "spike_rightclick_autotest.py"
    venv_py = ROOT / ".venv" / "Scripts" / "python.exe"
    if spike.exists() and venv_py.exists():
        result = subprocess.run(
            [str(venv_py), str(spike)],
            capture_output=True, text=True, timeout=60
        )
        print(f"  [spike done] exit={result.returncode}")
        if result.stdout: print("  OUT:", result.stdout[-500:])
        if result.stderr: print("  ERR:", result.stderr[-300:])

spike_thread = threading.Thread(target=run_spike_after_delay, args=(20,), daemon=True)
spike_thread.start()

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

sc_hook.unload()
sess.detach()

# ── 保存与分析 ────────────────────────────────────────────────────────────────
ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"ipc_qt_{ts}.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for m in all_messages:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

# 解析 JSON payload
payloads = []
for m in data_messages:
    msg_txt = m["msg"]
    if "json_payload:" in msg_txt:
        jp = msg_txt.split("json_payload:")[-1].strip()
        if jp and jp != "":
            try:
                obj = json.loads(jp)
                payloads.append({"t": m["t"], "payload": obj})
            except Exception:
                payloads.append({"t": m["t"], "payload": jp[:200]})

print(f"\n[*] 完成: {len(all_messages)} 条消息  JSON payloads={len(payloads)}")
print(f"    Output: {out}")

if payloads:
    print("\n=== 捕获到的 JSON 命令 ===")
    seen_cmds = set()
    for p in payloads:
        obj = p["payload"]
        cmd = obj.get("command","") if isinstance(obj, dict) else str(obj)[:50]
        if cmd not in seen_cmds:
            seen_cmds.add(cmd)
            print(f"  [{p['t']}] command={cmd!r}")
            if isinstance(obj, dict):
                print(f"    data keys: {list(obj.get('data', {}).keys())}")
