"""
ipc_pipe_v2.py
————————————————————————————————————————
1. 用 NtQuerySystemInformation(SystemHandleInformation) 枚举目标进程的
   所有 Handle，复制到当前进程后通过 NtQueryObject 获取对象名。
2. 筛选出指向 WXWork IPC 命名管道的 handle 数值。
3. 用 Frida 在目标进程中注入 hook，过滤这些 handle 号的 NtWriteFile / NtReadFile。

用法：
  C:\\Users\\LENOVO\\AppData\\Local\\Programs\\Python\\Python311\\python.exe ^
      scripts/wecom_re/ipc_pipe_v2.py [秒数=40]
"""
import sys, time, json, ctypes, ctypes.wintypes, struct, subprocess, re
from datetime import datetime
from pathlib import Path

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 40
OUT_DIR  = Path(__file__).resolve().parent.parent.parent / "runtime" / "wecom_re"
OUT_DIR.mkdir(parents=True, exist_ok=True)

import frida

# ── Win32 helper: 枚举进程 Handle → 获取管道名 ────────────────────────────────

PIPE_PATTERNS = ["WXWork.IPC-Qt", "WXFlutter.IPC-WXWork",
                 "WXWork.IPC-WeDoc", "WXWork.IPC-WeDrive"]

NT_STATUS_SUCCESS              = 0
NT_STATUS_BUFFER_OVERFLOW      = 0x80000005
NT_STATUS_BUFFER_TOO_SMALL     = 0xC0000023
NT_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004   # ← 缓冲区不足时最常见的返回值
SystemHandleInformation        = 16
ObjectNameInformation          = 1

# ctypes 用 c_long（有符号），大值需转换
def _nt_status_eq(status: int, expected: int) -> bool:
    """比较 NT STATUS，兼容有符号/无符号差异。"""
    return (status & 0xFFFFFFFF) == (expected & 0xFFFFFFFF)

class SYSTEM_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = [
        ("ProcessId",        ctypes.c_ushort),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex",  ctypes.c_ubyte),
        ("HandleAttributes", ctypes.c_ubyte),
        ("HandleValue",      ctypes.c_ushort),
        ("Object",           ctypes.c_void_p),
        ("GrantedAccess",    ctypes.c_ulong),
    ]

ntdll  = ctypes.WinDLL("ntdll")
kernel = ctypes.WinDLL("kernel32")

ntdll.NtQuerySystemInformation.restype  = ctypes.c_long
ntdll.NtQueryObject.restype             = ctypes.c_long
kernel.DuplicateHandle.restype          = ctypes.c_bool
kernel.CloseHandle.restype              = ctypes.c_bool

def get_wxwork_pipe_handles(target_pid: int) -> dict[int, str]:
    """返回 {handle_value: pipe_name} — 仅限 target_pid 进程中的目标管道。"""
    result = {}

    # 1. 获取全系统句柄列表
    size = 0x100000
    while True:
        buf = ctypes.create_string_buffer(size)
        needed = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(
            SystemHandleInformation, buf, len(buf), ctypes.byref(needed))
        if _nt_status_eq(status, NT_STATUS_SUCCESS):
            break
        if any(_nt_status_eq(status, c) for c in (
                NT_STATUS_BUFFER_OVERFLOW,
                NT_STATUS_BUFFER_TOO_SMALL,
                NT_STATUS_INFO_LENGTH_MISMATCH)):
            size = max(needed.value + 0x10000, size * 2)
            if size > 64 * 1024 * 1024:
                print("  buffer too large, giving up")
                return result
        else:
            print(f"  NtQuerySystemInformation failed: {status & 0xFFFFFFFF:#010x}")
            return result

    # 2. 解析句柄列表
    count = ctypes.c_ulong.from_buffer_copy(buf[:4]).value
    entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)
    entries_start = 4

    curr_pid = kernel.GetCurrentProcessId()
    curr_proc = kernel.OpenProcess(0x1F0FFF, False, curr_pid)
    target_proc = kernel.OpenProcess(0x40 | 0x10, False, target_pid)  # PROCESS_DUP_HANDLE | PROCESS_QUERY_INFO
    if not target_proc:
        print(f"  Cannot open target process {target_pid}")
        return result

    for i in range(count):
        offset = entries_start + i * entry_size
        entry = SYSTEM_HANDLE_TABLE_ENTRY_INFO.from_buffer_copy(buf[offset:offset + entry_size])
        if entry.ProcessId != target_pid:
            continue

        # 3. 复制句柄到当前进程（只读）
        dup_handle = ctypes.wintypes.HANDLE()
        ok = kernel.DuplicateHandle(
            target_proc, ctypes.c_void_p(entry.HandleValue),
            curr_proc,   ctypes.byref(dup_handle),
            0, False, 2  # DUPLICATE_SAME_ACCESS
        )
        if not ok:
            continue

        # 4. 查询对象名
        try:
            name_buf = ctypes.create_string_buffer(1024)
            ret_len  = ctypes.c_ulong(0)
            status2  = ntdll.NtQueryObject(
                dup_handle, ObjectNameInformation,
                name_buf, len(name_buf), ctypes.byref(ret_len))
            if _nt_status_eq(status2, NT_STATUS_SUCCESS) and ret_len.value > 4:
                # UNICODE_STRING: Length(2) + MaxLength(2) + Buffer*(4 or 8)
                ptr_size = ctypes.sizeof(ctypes.c_void_p)
                name_off = 4 + ptr_size
                raw = name_buf.raw
                length = struct.unpack_from("<H", raw, 0)[0]
                if length > 0:
                    name_bytes = raw[name_off:name_off + length]
                    name_str   = name_bytes.decode("utf-16-le", errors="ignore")
                    # 过滤目标管道
                    if any(p in name_str for p in PIPE_PATTERNS):
                        result[entry.HandleValue] = name_str
        except Exception:
            pass
        finally:
            kernel.CloseHandle(dup_handle)

    kernel.CloseHandle(target_proc)
    return result


def get_listen_pid(port=9882):
    out = subprocess.check_output("netstat -ano", shell=True, text=True, errors="ignore")
    for line in out.splitlines():
        if str(port) in line and "LISTENING" in line:
            m = re.search(r'\s+(\d+)\s*$', line.strip())
            if m: return int(m.group(1))
    return None


# ── 找目标进程 ────────────────────────────────────────────────────────────────
server_pid = get_listen_pid(9882)
print(f"[*] Main WXWork PID = {server_pid}")

dev = frida.get_local_device()
all_procs = dev.enumerate_processes()
wx_procs  = [(p.pid, p.name) for p in all_procs if 'wxwork' in p.name.lower()]

# ── 对每个进程枚举管道 Handle ─────────────────────────────────────────────────
per_proc_handles: dict[int, dict[int, str]] = {}
for pid, name in wx_procs:
    handles = get_wxwork_pipe_handles(pid)
    if handles:
        per_proc_handles[pid] = handles
        print(f"  [{name}:{pid}] found {len(handles)} pipe handles:")
        for h, n in handles.items():
            print(f"    handle={h:#06x}  {n}")

if not per_proc_handles:
    print("[!] 未找到任何目标管道 Handle — 权限不足或管道名称已变更")
    print("    尝试以管理员权限运行本脚本")
    sys.exit(1)

# ── 构造 Frida hook JS（每个进程使用各自的 handle 列表）─────────────────────
JS_TEMPLATE = r"""
'use strict';
var PIPE_HANDLES_HEX = [HANDLE_LIST];
var PIPE_HANDLES = PIPE_HANDLES_HEX.map(function(h){ return h; });
var DUMP_MAX = 512;

function dumpBytes(buf, maxLen) {
    var b = new Uint8Array(buf);
    var len = Math.min(b.length, maxLen);
    var rows = [];
    for (var r = 0; r < len; r += 16) {
        var end = Math.min(r + 16, len); var h2 = ''; var a = '';
        for (var i = r; i < end; i++) {
            h2 += ('0' + b[i].toString(16)).slice(-2) + ' ';
            a  += (b[i] >= 0x20 && b[i] < 0x7f) ? String.fromCharCode(b[i]) : '.';
        }
        rows.push(('000' + r.toString(16)).slice(-4) + '  ' + h2.padEnd(48) + ' |' + a + '|');
    }
    if (b.length > maxLen) rows.push('  ... (' + b.length + ' bytes)');
    return rows.join('\n');
}

function emit(s) { try { send({ pid: Process.id, msg: s }); } catch(_) {} }

var ntdll = Process.getModuleByName('ntdll.dll');

// NtWriteFile(HANDLE, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcCtx,
//             PIO_STATUS_BLOCK IoStatus, PVOID Buffer, ULONG Length, ...)
var ntWriteFile = ntdll.findExportByName('NtWriteFile');
if (ntWriteFile) {
    Interceptor.attach(ntWriteFile, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (PIPE_HANDLES.indexOf(h) < 0) return;
            var n = a[6].toInt32(); if (n <= 0) return;
            try {
                var d = a[5].readByteArray(Math.min(n, DUMP_MAX));
                emit('[NtWriteFile handle=' + h + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) { emit('[NtWriteFile err] ' + e); }
        }
    });
}

// NtReadFile(HANDLE, HANDLE Event, PIO_APC_ROUTINE, PVOID ApcCtx,
//            PIO_STATUS_BLOCK IoStatus, PVOID Buffer, ULONG Length, ...)
var ntReadFile = ntdll.findExportByName('NtReadFile');
if (ntReadFile) {
    Interceptor.attach(ntReadFile, {
        onEnter: function(a) {
            var h = a[0].toInt32();
            if (PIPE_HANDLES.indexOf(h) >= 0) {
                this.h = h; this.buf = a[5]; this.iosb = a[4];
            } else {
                this.h = 0;
            }
        },
        onLeave: function(ret) {
            if (!this.h) return;
            var status = ret.toInt32();
            // 0 = success, 0x103 = STATUS_PENDING (async IO)
            if (status !== 0 && status !== 0x103) return;
            try {
                var n = this.iosb.add(4).readU32();  // IO_STATUS_BLOCK.Information
                if (n <= 0) return;
                var d = this.buf.readByteArray(Math.min(n, DUMP_MAX));
                emit('[NtReadFile handle=' + this.h + '] len=' + n + '\n' + dumpBytes(d, DUMP_MAX));
            } catch(e) {}
        }
    });
}

emit('[pipe_hook_v2 ready] pid=' + Process.id + ' handles=[' + PIPE_HANDLES.join(',') + ']');
"""

# ── 注入 ─────────────────────────────────────────────────────────────────────
all_messages = []
sessions, scripts = [], []

def make_handler(pid, name):
    def on_msg(msg, data):
        if msg.get("type") == "send":
            pl = msg["payload"]
            entry = {"t": datetime.now().isoformat(), "pid": pl.get("pid", pid),
                     "proc": name, "msg": pl.get("msg", "")}
            all_messages.append(entry)
            txt = entry["msg"][:150]
            print(f"[{name}:{entry['pid']}] {txt}")
        elif msg.get("type") == "error":
            print(f"[ERR pid={pid}]", msg.get("description","")[:200])
    return on_msg

for pid, name in wx_procs:
    handles_for_pid = per_proc_handles.get(pid, {})
    if not handles_for_pid:
        continue
    handle_list = ", ".join(str(h) for h in handles_for_pid.keys())
    js = JS_TEMPLATE.replace("HANDLE_LIST", handle_list)
    try:
        sess = dev.attach(pid)
        sc   = sess.create_script(js)
        sc.on("message", make_handler(pid, name))
        sc.load()
        sessions.append(sess); scripts.append(sc)
        print(f"  [+] injected pid={pid} {name}  handles={list(handles_for_pid.keys())}")
    except Exception as e:
        print(f"  [-] SKIP pid={pid} {name}: {e}")

if not scripts:
    print("[!] 没有进程被注入，退出")
    sys.exit(1)

print(f"\n[*] Capturing {DURATION}s — 请在企微中操作（发消息/切换聊天/打开联系人）")
print("    Ctrl+C 可提前结束\n")

try:
    time.sleep(DURATION)
except KeyboardInterrupt:
    print("[*] 中断")

# ── 保存 ─────────────────────────────────────────────────────────────────────
ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
out = OUT_DIR / f"ipc_pipe2_{ts}.jsonl"
with open(out, "w", encoding="utf-8") as f:
    for m in all_messages:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")

for sc in scripts:
    try: sc.unload()
    except Exception: pass
for sess in sessions:
    try: sess.detach()
    except Exception: pass

writes = [m for m in all_messages if "NtWriteFile" in m["msg"]]
reads  = [m for m in all_messages if "NtReadFile"  in m["msg"]]

print(f"\n[*] 完成: {len(all_messages)} 条消息 -> {out}")
print(f"    NtWriteFile={len(writes)}  NtReadFile={len(reads)}")

if writes:
    print("\n=== 首条 WRITE payload ===")
    print(writes[0]["msg"][:1000])
if reads:
    print("\n=== 首条 READ payload ===")
    print(reads[0]["msg"][:1000])
