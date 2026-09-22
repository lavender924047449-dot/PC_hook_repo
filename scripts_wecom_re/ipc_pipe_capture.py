"""
ipc_pipe_capture.py
————————————————————————————————————————
Hook Named Pipe IPC: 捕获 WXWork 进程对
  Tencent.WXWork.IPC-Qt-*  /  Tencent.WXFlutter.IPC-WXWork
命名管道的 ReadFile / WriteFile / NtReadFile / NtWriteFile 调用。

用法：
  C:\\Users\\LENOVO\\AppData\\Local\\Programs\\Python\\Python311\\python.exe ^
      scripts/wecom_re/ipc_pipe_capture.py [秒数=40]

运行期间在企微中做各种操作（发消息、切换聊天、打开联系人等）。
"""
import sys, time, json, re, subprocess
from datetime import datetime
from pathlib import Path

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 40
OUT_DIR  = Path(__file__).resolve().parent.parent.parent / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

import frida

JS_HOOK = r"""
'use strict';
var PIPE_PATTERNS = ['WXWork.IPC-Qt', 'WXFlutter.IPC-WXWork', 'WXWork.IPC-WeDoc', 'WXWork.IPC-WeDrive'];
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

function emit(s) { try { send({ pid: Process.id, msg: s }); } catch(_) {} }

// handle(int) -> pipe_name(str)
var pipeHandles = {};

// ── hook CreateFileA / CreateFileW ────────────────────────────────────────────

function checkPipeName(name) {
    for (var i = 0; i < PIPE_PATTERNS.length; i++) {
        if (name.indexOf(PIPE_PATTERNS[i]) >= 0) return true;
    }
    return false;
}

var k32 = Process.getModuleByName('kernel32.dll');

function hookCreateFile(exportName, readStr) {
    var fn = k32.findExportByName(exportName);
    if (!fn) return;
    Interceptor.attach(fn, {
        onEnter: function(a) {
            try {
                var name = readStr ? a[0].readUtf16String() : a[0].readAnsiString();
                if (name && checkPipeName(name)) { this.pipeName = name; }
            } catch(e) {}
        },
        onLeave: function(ret) {
            if (!this.pipeName) return;
            var h = ret.toInt32();
            if (h && h !== -1) {
                pipeHandles[h] = this.pipeName;
                emit('[CreateFile] handle=' + h + ' pipe=' + this.pipeName);
            }
        }
    });
}

hookCreateFile('CreateFileA', false);
hookCreateFile('CreateFileW', true);

// ── hook CloseHandle ──────────────────────────────────────────────────────────
var closeFn = k32.findExportByName('CloseHandle');
if (closeFn) {
    Interceptor.attach(closeFn, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (h in pipeHandles) { delete pipeHandles[h]; }
        }
    });
}

// ── hook WriteFile ────────────────────────────────────────────────────────────
// WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nBytesToWrite, LPDWORD lpWritten, LPOVERLAPPED)
var writeFn = k32.findExportByName('WriteFile');
if (writeFn) {
    Interceptor.attach(writeFn, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (!(h in pipeHandles)) return;
            var n = a[2].toInt32(); if (n <= 0) return;
            var d = a[1].readByteArray(Math.min(n, DUMP_MAX));
            emit('[WRITE->pipe=' + pipeHandles[h] + '] handle=' + h + ' len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
        }
    });
}

// ── hook ReadFile ─────────────────────────────────────────────────────────────
// ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nToRead, LPDWORD lpRead, LPOVERLAPPED)
var readFn = k32.findExportByName('ReadFile');
if (readFn) {
    Interceptor.attach(readFn, {
        onEnter: function(a) { this.a = a; },
        onLeave: function(ret) {
            if (!ret.toInt32()) return;
            var h = this.a[0].toInt32();
            if (!(h in pipeHandles)) return;
            var lpRead = this.a[3];
            var n = lpRead.isNull() ? 0 : lpRead.readU32();
            if (n <= 0) return;
            var d = this.a[1].readByteArray(Math.min(n, DUMP_MAX));
            emit('[READ<-pipe=' + pipeHandles[h] + '] handle=' + h + ' len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
        }
    });
}

// ── 也 hook NtWriteFile / NtReadFile（ntdll 层，部分应用绕过 kernel32）─────────
try {
    var ntdll = Process.getModuleByName('ntdll.dll');
    // NtWriteFile(HANDLE, HANDLE Event, PIO_APC_ROUTINE, PVOID ApcCtx, PIO_STATUS_BLOCK, PVOID Buf, ULONG Len, ...)
    var ntWrite = ntdll.findExportByName('NtWriteFile');
    if (ntWrite) {
        Interceptor.attach(ntWrite, {
            onEnter: function(a) {
                var h = a[0].toInt32();
                if (!(h in pipeHandles)) return;
                var n = a[6].toInt32(); if (n <= 0) return;
                var d = a[5].readByteArray(Math.min(n, DUMP_MAX));
                emit('[NtWrite->pipe=' + pipeHandles[h] + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            }
        });
    }
    var ntRead = ntdll.findExportByName('NtReadFile');
    if (ntRead) {
        Interceptor.attach(ntRead, {
            onEnter: function(a) {
                this.h = a[0].toInt32();
                this.bufPtr = a[5];
                this.statusBlock = a[4];  // IO_STATUS_BLOCK* - Information field = bytes read
            },
            onLeave: function(ret) {
                if (!(this.h in pipeHandles)) return;
                if (ret.toInt32() !== 0 && ret.toInt32() !== 0x103) return;  // 0 = success, 0x103 = pending
                try {
                    var n = this.statusBlock.add(Process.pointerSize).readU32();  // Information field
                    if (n <= 0) return;
                    var d = this.bufPtr.readByteArray(Math.min(n, DUMP_MAX));
                    emit('[NtRead<-pipe=' + pipeHandles[this.h] + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
                } catch(e) {}
            }
        });
    }
} catch(e) { emit('[ntdll hook] ' + e); }

emit('[pipe_hook ready] pid=' + Process.id + ' patterns=' + PIPE_PATTERNS.join('|'));
"""

# ── 确定注入目标 ──────────────────────────────────────────────────────────────
def get_listen_pid(port=9882):
    out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
    for line in out.splitlines():
        if str(port) in line and "LISTENING" in line:
            m = re.search(r'\s+(\d+)\s*$', line.strip())
            if m: return int(m.group(1))
    return None

server_pid = get_listen_pid(9882)
print(f"[*] Main WXWork PID (server) = {server_pid}")

dev = frida.get_local_device()
all_procs = dev.enumerate_processes()
# 注入全部 WXWork 相关进程（含主进程，因为它也可能是 pipe 客户端）
wx_procs = [(p.pid, p.name) for p in all_procs if 'wxwork' in p.name.lower()]
print(f"[*] Injecting into {len(wx_procs)} processes: {wx_procs}")

all_messages = []
sessions, scripts = [], []

def make_handler(pid, name):
    def on_msg(msg, data):
        if msg.get("type") == "send":
            pl = msg["payload"]
            entry = {"t": datetime.now().isoformat(), "pid": pl.get("pid", pid),
                     "proc": name, "msg": pl.get("msg", "")}
            all_messages.append(entry)
            txt = entry["msg"]
            if len(txt) > 120: txt = txt[:120] + "..."
            print(f"[{name}:{entry['pid']}] {txt}")
        elif msg.get("type") == "error":
            print(f"[ERR pid={pid}]", msg.get("description","")[:200])
    return on_msg

for pid, name in wx_procs:
    try:
        sess = dev.attach(pid)
        sc   = sess.create_script(JS_HOOK)
        sc.on("message", make_handler(pid, name))
        sc.load()
        sessions.append(sess); scripts.append(sc)
        print(f"  [+] injected pid={pid} {name}")
    except Exception as e:
        print(f"  [-] SKIP pid={pid} {name}: {e}")

print(f"\n[*] Capturing {DURATION}s — 请在企微中操作（发消息/切换聊天/打开联系人）")
print("    Ctrl+C 可提前停止\n")

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

# ── 保存 ─────────────────────────────────────────────────────────────────────
ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"ipc_pipe_{ts}.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for m in all_messages:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

for sc in scripts:
    try: sc.unload()
    except Exception: pass
for sess in sessions:
    try: sess.detach()
    except Exception: pass

# ── 汇总 ─────────────────────────────────────────────────────────────────────
creates = [m for m in all_messages if "[CreateFile]" in m["msg"]]
writes  = [m for m in all_messages if "[WRITE->" in m["msg"] or "[NtWrite->" in m["msg"]]
reads   = [m for m in all_messages if "[READ<-"  in m["msg"] or "[NtRead<-"  in m["msg"]]

print(f"\n[*] 完成: {len(all_messages)} 条消息 -> {out}")
print(f"    CreateFile={len(creates)}  WRITE={len(writes)}  READ={len(reads)}")

if writes:
    print("\n=== 首条 WRITE payload ===")
    print(writes[0]["msg"][:1000])
if reads:
    print("\n=== 首条 READ payload ===")
    print(reads[0]["msg"][:1000])
