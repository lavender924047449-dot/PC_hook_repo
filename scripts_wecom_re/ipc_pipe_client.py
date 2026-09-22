"""
ipc_pipe_client.py
————————————————————————————————————————
尝试从 Python 直接连接企微 Named Pipe，
发送探测 JSON 命令，看服务端如何响应。

企微管道路径示例（运行时从系统查询）：
  \\\\.\pipe\\LENOVO-Tencent.WXWork.IPC-Qt-XXXXXXX

用法：
  python scripts/wecom_re/ipc_pipe_client.py
"""
import sys, os, time, json, struct, ctypes, ctypes.wintypes
from pathlib import Path
from datetime import datetime

# ── Win32 命名管道 API ────────────────────────────────────────────────────────

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

k32.CreateFileW.restype  = ctypes.wintypes.HANDLE
k32.CreateFileW.argtypes = [
    ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
    ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE
]
k32.WaitNamedPipeW.restype  = ctypes.wintypes.BOOL
k32.WaitNamedPipeW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD]
k32.WriteFile.restype  = ctypes.wintypes.BOOL
k32.WriteFile.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p
]
k32.ReadFile.restype  = ctypes.wintypes.BOOL
k32.ReadFile.argtypes = [
    ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p
]
k32.CloseHandle.restype  = ctypes.wintypes.BOOL
k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

# ── 枚举系统中的企微管道 ─────────────────────────────────────────────────────

def list_wxwork_pipes():
    import ctypes.wintypes
    import os
    pipes = []
    for name in os.listdir(r"\\.\pipe"):
        if "WXWork.IPC" in name or "WXFlutter.IPC" in name:
            pipes.append(r"\\.\pipe\\" + name)
    return pipes

# ── IPC 帧编解码 ──────────────────────────────────────────────────────────────

def encode_frame(payload: dict) -> bytes:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    header = struct.pack("<IB", len(body), 0x00)
    return header + body

def decode_frame(data: bytes):
    if len(data) < 5:
        return None
    body_len = struct.unpack_from("<I", data, 0)[0]
    flags    = data[4]
    body     = data[5:5 + body_len]
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return {"raw": body.hex(), "flags": flags}

# ── 连接管道并通信 ─────────────────────────────────────────────────────────────

class PipeClient:
    def __init__(self, pipe_path: str):
        self.pipe_path = pipe_path
        self.handle    = None

    def connect(self, timeout_ms=5000):
        # WaitNamedPipe 等待管道可用
        k32.WaitNamedPipeW(self.pipe_path, timeout_ms)
        h = k32.CreateFileW(
            self.pipe_path,
            GENERIC_READ | GENERIC_WRITE,
            0, None,
            OPEN_EXISTING,
            0, None
        )
        if h == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise OSError(f"CreateFile failed: error {err:#x}")
        self.handle = h
        return self

    def send(self, payload: dict):
        frame = encode_frame(payload)
        written = ctypes.wintypes.DWORD(0)
        ok = k32.WriteFile(self.handle, frame, len(frame), ctypes.byref(written), None)
        if not ok:
            raise OSError(f"WriteFile failed: {ctypes.get_last_error():#x}")
        return written.value

    def recv(self, max_bytes=65536, timeout_s=3):
        buf = ctypes.create_string_buffer(max_bytes)
        read_bytes = ctypes.wintypes.DWORD(0)
        ok = k32.ReadFile(self.handle, buf, max_bytes, ctypes.byref(read_bytes), None)
        if not ok:
            err = ctypes.get_last_error()
            if err == 109:  # ERROR_BROKEN_PIPE
                return None
            raise OSError(f"ReadFile failed: {err:#x}")
        return bytes(buf.raw[:read_bytes.value])

    def close(self):
        if self.handle:
            k32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

# ── 主测试逻辑 ────────────────────────────────────────────────────────────────

def run_probe(pipe_path: str, commands):
    print(f"\n{'='*60}")
    print(f"Probing: {pipe_path}")
    print(f"{'='*60}")

    try:
        client = PipeClient(pipe_path)
        client.connect()
        print("  [+] Connected!")
    except OSError as e:
        print(f"  [-] Connect failed: {e}")
        return

    with client:
        for cmd in commands:
            print(f"\n  --> Sending: {json.dumps(cmd)[:80]}")
            try:
                written = client.send(cmd)
                print(f"      sent {written} bytes")
            except OSError as e:
                print(f"      send failed: {e}")
                break

            try:
                resp = client.recv()
                if resp:
                    parsed = decode_frame(resp)
                    print(f"  <-- Response ({len(resp)}B): {json.dumps(parsed, ensure_ascii=False)[:200]}")
                else:
                    print("  <-- Pipe closed by server")
            except OSError as e:
                print(f"  <-- recv error: {e}")
            time.sleep(0.5)

def gen_ac_id():
    import random, string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))

# 测试命令集
PROBE_COMMANDS = [
    # WeDrive heartbeat — 已知有效格式
    lambda: {
        "command": f"wework_isActive-{gen_ac_id()}",
        "data": {
            "ac_id": gen_ac_id(),
            "message": "",
            "ret": 0,
            "ipc_send_time": int(time.time() * 1000),
            "data": {"ppid": "28432"}
        }
    },
    # 猜测的命令
    lambda: {"command": "ping",   "data": {}, "ac_id": gen_ac_id(), "ipc_send_time": int(time.time()*1000)},
    lambda: {"command": "getInfo","data": {}, "ac_id": gen_ac_id(), "ipc_send_time": int(time.time()*1000)},
    lambda: {"command": "getVersion", "data": {}, "ac_id": gen_ac_id()},
    lambda: {"command": "wework_getSession", "data": {}, "ac_id": gen_ac_id()},
    lambda: {"command": "openIM",  "data": {}, "ac_id": gen_ac_id()},
]

if __name__ == "__main__":
    print("[*] 枚举企微 Named Pipe...")
    pipes = list_wxwork_pipes()
    print(f"  Found {len(pipes)} pipes:")
    for p in pipes:
        print(f"    {p}")

    for pipe_path in pipes:
        cmds = [f() for f in PROBE_COMMANDS]
        run_probe(pipe_path, cmds)
