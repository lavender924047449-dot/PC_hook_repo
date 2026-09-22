"""
ipc_pipe_v3.py  — 在目标进程内部枚举管道 handle，再 hook NtWriteFile/NtReadFile。

Frida agent 在目标进程内调用 NtQueryObject，扫描 0x4..0x1000 的句柄号，
找出匹配 WXWork IPC 命名管道的 handle，然后对这些 handle hook 读写。

用法：
  C:\\Users\\LENOVO\\AppData\\Local\\Programs\\Python\\Python311\\python.exe ^
      scripts/wecom_re/ipc_pipe_v3.py [秒数=40]
"""
import sys, time, json, subprocess, re
from datetime import datetime
from pathlib import Path

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 40
OUT_DIR  = Path(__file__).resolve().parent.parent.parent / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

import frida

# JS agent: 在目标进程内部枚举 Handle 再 hook
JS = r"""
'use strict';

var PIPE_PATTERNS = ['WXWork.IPC-Qt', 'WXFlutter.IPC-WXWork',
                     'WXWork.IPC-WeDoc', 'WXWork.IPC-WeDrive'];
var DUMP_MAX = 512;

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

// ── 内部枚举 Handle ───────────────────────────────────────────────────────────
var ntdll = Process.getModuleByName('ntdll.dll');

// NtQueryObject(Handle, ObjectInformationClass, ObjectInfo, ObjectInfoLength, ReturnLength)
var NtQueryObject = new NativeFunction(
    ntdll.getExportByName('NtQueryObject'),
    'int', ['pointer', 'int', 'pointer', 'uint', 'pointer']
);

var ObjectNameInformation = 1;
var STATUS_SUCCESS        = 0;

function getHandleName(handleInt) {
    // handle 必须作为指针传入（Windows HANDLE = uintptr_t）
    var h = ptr(handleInt);
    var buf = Memory.alloc(1024);
    var rlen = Memory.alloc(4);
    var status = NtQueryObject(h, ObjectNameInformation, buf, 1024, rlen);
    if (status !== STATUS_SUCCESS) return null;
    // UNICODE_STRING: USHORT Length, USHORT MaxLength, PWSTR Buffer
    var nameLen = buf.readU16();
    if (nameLen === 0) return null;
    var ptrSize = Process.pointerSize;
    var strPtr  = buf.add(4).readPointer();  // Buffer pointer
    if (strPtr.isNull()) return null;
    return strPtr.readUtf16String(nameLen / 2);
}

// 扫描 handle 范围
var pipeHandles = [];   // array of handle int values
var pipeHandleNames = {};  // handle -> short name

emit('[scan] Scanning handles 0x4..0xFFF ...');
for (var h = 4; h <= 0xFFF; h += 4) {
    try {
        var name = getHandleName(h);
        if (name && PIPE_PATTERNS.some(function(p){ return name.indexOf(p) >= 0; })) {
            pipeHandles.push(h);
            // 取管道名中 IPC- 之后的部分作为简短标签
            var label = name.replace(/.*IPC-/, 'IPC-').substring(0, 40);
            pipeHandleNames[h] = label;
            emit('[found] handle=' + h + ' name=' + name);
        }
    } catch(e) {
        // 无效 handle，忽略
    }
}

emit('[scan] Done. Found ' + pipeHandles.length + ' pipe handle(s): ' + pipeHandles.join(', '));

if (pipeHandles.length === 0) {
    emit('[warn] No pipe handles found in this process. Try another process.');
}

// ── hook NtWriteFile / NtReadFile ─────────────────────────────────────────────

var ntWriteFile = ntdll.findExportByName('NtWriteFile');
if (ntWriteFile && pipeHandles.length > 0) {
    Interceptor.attach(ntWriteFile, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (pipeHandles.indexOf(h) < 0) return;
            var n = a[6].toInt32(); if (n <= 0 || n > 65536) return;
            try {
                var d = a[5].readByteArray(Math.min(n, DUMP_MAX));
                var label = pipeHandleNames[h] || ('h=' + h);
                emit('[WRITE ' + label + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) { emit('[NtWriteFile err] ' + e); }
        }
    });
    emit('[hook] NtWriteFile attached');
}

var ntReadFile = ntdll.findExportByName('NtReadFile');
if (ntReadFile && pipeHandles.length > 0) {
    Interceptor.attach(ntReadFile, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (pipeHandles.indexOf(h) >= 0) {
                this.h    = h;
                this.buf  = a[5];
                this.iosb = a[4];   // IO_STATUS_BLOCK*
            } else {
                this.h = 0;
            }
        },
        onLeave: function(ret) {
            if (!this.h) return;
            var status = ret.toInt32();
            // STATUS_SUCCESS(0) or STATUS_PENDING(0x103)
            if (status !== 0 && status !== 0x103) return;
            try {
                // IO_STATUS_BLOCK = { NTSTATUS/PVOID Status; ULONG_PTR Information; }
                // Information = bytes transferred
                var ptrSize = Process.pointerSize;
                var n = this.iosb.add(ptrSize).readU32();
                if (n <= 0 || n > 65536) return;
                var d = this.buf.readByteArray(Math.min(n, DUMP_MAX));
                var label = pipeHandleNames[this.h] || ('h=' + this.h);
                emit('[READ ' + label + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) {}
        }
    });
    emit('[hook] NtReadFile attached');
}

emit('[pipe_hook_v3 ready] pid=' + Process.id);
"""

def get_listen_pid(port=9882):
    out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
    for line in out.splitlines():
        if str(port) in line and "LISTENING" in line:
            m = re.search(r'\s+(\d+)\s*$', line.strip())
            if m: return int(m.group(1))
    return None

server_pid = get_listen_pid(9882)
dev = frida.get_local_device()
all_procs = dev.enumerate_processes()
wx_procs  = [(p.pid, p.name) for p in all_procs if 'wxwork' in p.name.lower()]

print(f"[*] Main WXWork PID = {server_pid}")
print(f"[*] Injecting into {len(wx_procs)} WXWork processes")

all_messages = []
sessions, scripts = [], []

def make_handler(pid, name):
    def on_msg(msg, data):
        if msg.get("type") == "send":
            pl = msg["payload"]
            entry = {"t": datetime.now().isoformat(),
                     "pid": pl.get("pid", pid), "proc": name, "msg": pl.get("msg","")}
            all_messages.append(entry)
            txt = entry["msg"]
            if len(txt) > 160: txt = txt[:160] + "..."
            print(f"  [{name}:{entry['pid']}] {txt}")
        elif msg.get("type") == "error":
            print(f"  [ERR pid={pid}]", msg.get("description","")[:200])
    return on_msg

for pid, name in wx_procs:
    try:
        sess = dev.attach(pid)
        sc   = sess.create_script(JS)
        sc.on("message", make_handler(pid, name))
        sc.load()
        sessions.append(sess); scripts.append(sc)
        print(f"  [+] injected pid={pid} {name}")
    except Exception as e:
        print(f"  [-] SKIP pid={pid} {name}: {e}")

print(f"\n[*] Capturing {DURATION}s — 请在企微中操作（发消息/切换聊天/联系人）")
print("    Ctrl+C 提前结束\n")

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

# ── 保存 ─────────────────────────────────────────────────────────────────────
ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"ipc_pipe3_{ts}.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for m in all_messages:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

for sc in scripts:
    try: sc.unload()
    except Exception: pass
for sess in sessions:
    try: sess.detach()
    except Exception: pass

found   = [m for m in all_messages if "[found]"  in m["msg"]]
writes  = [m for m in all_messages if "[WRITE "  in m["msg"]]
reads   = [m for m in all_messages if "[READ "   in m["msg"]]

print(f"\n[*] 完成: total={len(all_messages)}  pipes_found={len(found)}  WRITE={len(writes)}  READ={len(reads)}")
print(f"    Output: {out}")

if writes:
    print("\n=== 首条 WRITE payload ===")
    print(writes[0]["msg"][:1200])
if reads:
    print("\n=== 首条 READ payload ===")
    print(reads[0]["msg"][:1200])
