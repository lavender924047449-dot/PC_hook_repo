"""
ipc_pipe_final.py
对 WXWork 主进程中已知的 Named Pipe handle 注入
NtReadFile / NtWriteFile hook，捕获 IPC 流量。

用法：
  python scripts/wecom_re/ipc_pipe_final.py [秒数=60]
"""
import sys, time, json, subprocess, re
from datetime import datetime
from pathlib import Path

# 无缓冲输出
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 60
OUT_DIR  = Path(__file__).resolve().parent.parent.parent / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

import frida

# ── 动态扫描找管道 handle ─────────────────────────────────────────────────────

SCAN_JS = r"""
'use strict';
var PIPE_PATTERNS = ['WXWork.IPC', 'WXFlutter.IPC', 'WeWork.IPC'];
var ntdll = Process.getModuleByName('ntdll.dll');
var NtQueryObject = new NativeFunction(ntdll.getExportByName('NtQueryObject'),
    'int', ['pointer', 'int', 'pointer', 'uint', 'pointer']);
var ObjectNameInfo = 1;

var result = {};
for (var h = 4; h <= 0x8000; h += 4) {
    var buf = Memory.alloc(2048);
    var rl  = Memory.alloc(4);
    if (NtQueryObject(ptr(h), ObjectNameInfo, buf, 2048, rl) !== 0) continue;
    var nameLen = buf.readU16();
    if (nameLen === 0) continue;
    var strPtr = buf.add(4).readPointer();
    if (strPtr.isNull()) continue;
    try {
        var name = strPtr.readUtf16String(nameLen / 2);
        if (name && PIPE_PATTERNS.some(function(p){ return name.indexOf(p) >= 0; })) {
            result[h] = name;
        }
    } catch(e) {}
}
send({ type: 'scan_result', handles: result });
"""

def scan_pipe_handles(sess):
    """在已 attach 的会话中扫描管道 handle，返回 {handle_int: name}。"""
    result = {}
    done   = [False]

    def on_msg(msg, data):
        if msg.get("type") == "send":
            pl = msg.get("payload", {})
            if pl.get("type") == "scan_result":
                result.update(pl.get("handles", {}))
                done[0] = True
        elif msg.get("type") == "error":
            print(f"  [scan ERR] {msg.get('description','')[:200]}")
            done[0] = True

    sc = sess.create_script(SCAN_JS)
    sc.on("message", on_msg)
    sc.load()
    # 等待扫描完成（最多 20s）
    for _ in range(200):
        if done[0]:
            break
        time.sleep(0.1)
    sc.unload()
    return {int(k): v for k, v in result.items()}


# ── NtReadFile/NtWriteFile hook JS ───────────────────────────────────────────

HOOK_JS_TEMPLATE = r"""
'use strict';
var PIPE_HANDLES = [HANDLES_LIST];
var HANDLE_NAMES = HANDLE_NAMES_OBJ;
var DUMP_MAX = 1024;

function emit(s) { try { send({ pid: Process.id, msg: s }); } catch(_) {} }

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
    if (b.length > maxLen) rows.push('  ... (' + b.length + ' bytes total)');
    return rows.join('\n');
}

var ntdll = Process.getModuleByName('ntdll.dll');

// NtWriteFile(HANDLE, HANDLE Event, PIO_APC, PVOID ApcCtx,
//             PIO_STATUS_BLOCK, PVOID Buffer, ULONG Length, ...)
var ntWrite = ntdll.findExportByName('NtWriteFile');
if (ntWrite) {
    Interceptor.attach(ntWrite, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (PIPE_HANDLES.indexOf(h) < 0) return;
            var n = a[6].toInt32(); if (n <= 0 || n > 1048576) return;
            try {
                var d = a[5].readByteArray(Math.min(n, DUMP_MAX));
                var label = HANDLE_NAMES[h] || 'h=' + h;
                emit('[WRITE ' + label + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) { emit('[NtWriteFile err] ' + e); }
        }
    });
    emit('[hook] NtWriteFile attached');
}

// NtReadFile(HANDLE, HANDLE Event, PIO_APC, PVOID ApcCtx,
//            PIO_STATUS_BLOCK, PVOID Buffer, ULONG Length, ...)
var ntRead = ntdll.findExportByName('NtReadFile');
if (ntRead) {
    Interceptor.attach(ntRead, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            this.h    = (PIPE_HANDLES.indexOf(h) >= 0) ? h : 0;
            this.buf  = a[5];
            this.iosb = a[4];
        },
        onLeave: function(ret) {
            if (!this.h) return;
            var status = ret.toInt32();
            if (status !== 0 && status !== 0x103) return;
            try {
                var pSz = Process.pointerSize;
                var n   = this.iosb.add(pSz).readU32();
                if (n <= 0 || n > 1048576) return;
                var d = this.buf.readByteArray(Math.min(n, DUMP_MAX));
                var label = HANDLE_NAMES[this.h] || 'h=' + this.h;
                emit('[READ ' + label + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) {}
        }
    });
    emit('[hook] NtReadFile attached');
}

// 也 hook WriteFile (kernel32 层)
var k32 = Process.getModuleByName('kernel32.dll');
var writeFn = k32.findExportByName('WriteFile');
if (writeFn) {
    Interceptor.attach(writeFn, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (PIPE_HANDLES.indexOf(h) < 0) return;
            var n = a[2].toInt32(); if (n <= 0) return;
            try {
                var d = a[1].readByteArray(Math.min(n, DUMP_MAX));
                var label = HANDLE_NAMES[h] || 'h=' + h;
                emit('[WF-WRITE ' + label + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) {}
        }
    });
}

var readFn = k32.findExportByName('ReadFile');
if (readFn) {
    Interceptor.attach(readFn, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            this.h = (PIPE_HANDLES.indexOf(h) >= 0) ? h : 0;
            this.a = a;
        },
        onLeave: function(ret) {
            if (!this.h || !ret.toInt32()) return;
            try {
                var lpRead = this.a[3];
                var n = lpRead.isNull() ? 0 : lpRead.readU32();
                if (n <= 0) return;
                var d = this.a[1].readByteArray(Math.min(n, DUMP_MAX));
                var label = HANDLE_NAMES[this.h] || 'h=' + this.h;
                emit('[WF-READ ' + label + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) {}
        }
    });
}

emit('[pipe_hook_final ready] pid=' + Process.id + ' handles=[' + PIPE_HANDLES.join(',') + ']');
"""


def get_listen_pid(port=9882):
    out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
    for line in out.splitlines():
        if str(port) in line and "LISTENING" in line:
            m = re.search(r'\s+(\d+)\s*$', line.strip())
            if m: return int(m.group(1))
    return None

# ── 主流程 ────────────────────────────────────────────────────────────────────

main_pid = get_listen_pid(9882)
print(f"[*] Main WXWork PID = {main_pid}")

dev = frida.get_local_device()

# 1. 在主进程中扫描管道 handles
print("[*] Scanning pipe handles in main process...")
main_sess = dev.attach(main_pid)
pipe_handles = scan_pipe_handles(main_sess)

if not pipe_handles:
    print("[!] 未找到管道 handles，使用已知默认值")
    pipe_handles = {
        4944: "IPC-WXFlutter",
        4984: "IPC-TencentMeeting",
        5516: "IPC-WXWork(Flutter)",
        5528: "IPC-WeDrive",
        5912: "IPC-WeMailQt",
        5996: "IPC-Qt",
        6000: "IPC-WeDocQt",
    }
else:
    # 简化名称标签
    pipe_handles = {h: n.split("NamedPipe\\")[-1][:40] for h, n in pipe_handles.items()}

print(f"[*] Found {len(pipe_handles)} pipe handles:")
for h, n in sorted(pipe_handles.items()):
    print(f"    h={h}  {n}")

# 2. 构建 JS
handle_list = ", ".join(str(h) for h in pipe_handles.keys())
handle_names_obj = "{" + ", ".join(f"{h}: '{n}'" for h, n in pipe_handles.items()) + "}"
hook_js = HOOK_JS_TEMPLATE.replace("HANDLES_LIST", handle_list).replace("HANDLE_NAMES_OBJ", handle_names_obj)

# 3. 注入主进程 + 子进程
all_procs = dev.enumerate_processes()
wx_procs  = [(p.pid, p.name) for p in all_procs if 'wxwork' in p.name.lower()]

all_messages = []
sessions_all = [main_sess]
scripts_all  = []

def make_handler(pid, name):
    def on_msg(msg, data):
        if msg.get("type") == "send":
            pl = msg["payload"]
            entry = {"t": datetime.now().isoformat(),
                     "pid": pl.get("pid", pid), "proc": name, "msg": pl.get("msg","")}
            all_messages.append(entry)
            txt = entry["msg"][:180]
            print(f"  [{name}:{entry['pid']}] {txt}")
        elif msg.get("type") == "error":
            print(f"  [ERR pid={pid}]", msg.get("description","")[:200])
    return on_msg

for pid, name in wx_procs:
    try:
        sess = main_sess if pid == main_pid else dev.attach(pid)
        sc   = sess.create_script(hook_js)
        sc.on("message", make_handler(pid, name))
        sc.load()
        if pid != main_pid:
            sessions_all.append(sess)
        scripts_all.append(sc)
        print(f"  [+] hooked pid={pid} {name}")
    except Exception as e:
        print(f"  [-] SKIP pid={pid} {name}: {e}")

print(f"\n[*] Capturing {DURATION}s — 请在企微操作（切换聊天/发消息/开联系人）")
print("    Ctrl+C 可提前停止\n")
# 写 ready 信号文件
_ready_flag = OUT_DIR / "hook_ready.flag"
_ready_flag.write_text("ready")

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

# ── 保存 ─────────────────────────────────────────────────────────────────────
ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"ipc_pipe_final_{ts}.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for m in all_messages:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

for sc in scripts_all:
    try: sc.unload()
    except Exception: pass
for sess in sessions_all:
    try: sess.detach()
    except Exception: pass

writes = [m for m in all_messages if "WRITE" in m["msg"]]
reads  = [m for m in all_messages if "READ"  in m["msg"]]

print(f"\n[*] 完成: total={len(all_messages)}  WRITE={len(writes)}  READ={len(reads)}")
print(f"    Output: {out}")

if writes:
    print("\n=== 首条 WRITE payload ===")
    print(writes[0]["msg"][:1500])
if reads:
    print("\n=== 首条 READ payload ===")
    print(reads[0]["msg"][:1500])
