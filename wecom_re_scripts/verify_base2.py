# verify_base2.py -- 动态计算实际地址并验证字节序列
import frida, subprocess, sys, time

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def get_main_pid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in o.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])

pid = get_main_pid()
print(f"PID = {pid}", flush=True)

# 文档记录的 RVA（相对 WXWork.exe 基址的偏移，固定不变）
RVAS = {
    "dispatcher":    0x44AAA0,   # 任务分发器（55 8b ec 6a ff 68 开头）
    "SQL_builder":   0x2A3810,   # SQL 模板构建器（53 8b dc 83 ec 08）
    "CGI_hotpath":   0x390B39,   # CGI 热路径（高频）
    "CGI_layer":     0x39114B,   # CGI 层上一帧
    "WSASend_wrap1": 0x4493C0,   # WSASend 链 frame[6]
    "WSASend_wrap2": 0x449F60,   # WSASend 链 frame[7]
}

# 期望的函数序言（用于验证地址正确性）
EXPECTED_PROLOGS = {
    "dispatcher":    [0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68],  # PUSH EBP; MOV EBP,ESP; PUSH -1; PUSH ...
    "SQL_builder":   [0x53, 0x8b, 0xdc, 0x83, 0xec, 0x08],
    "WSASend_wrap1": [0x55, 0x8b, 0xec],
}

JS = """
var mods = Process.enumerateModules();
var base = null;
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === 'wxwork.exe') {
        base = mods[i].base;
        break;
    }
}

if (!base) { send({t:'err', msg:'WXWork.exe not found'}); }
send({t:'base', val: base.toString()});
"""

base_int = [None]

def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    if p.get("t") == "base":
        base_int[0] = int(p["val"], 16)
        print(f"\nWXWork.exe base = {p['val']}  (0x{base_int[0]:08X})")

sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(2)
sc.unload()
sess.detach()

if base_int[0] is None:
    print("ERROR: could not get base")
    exit(1)

base = base_int[0]
print(f"\n{'='*60}")
print(f"动态计算后的实际地址（基址 0x{base:08X}）：")
print(f"{'='*60}")

import ctypes, ctypes.wintypes

# 用 ReadProcessMemory 读字节验证
k32 = ctypes.windll.kernel32
proc = k32.OpenProcess(0x10, False, pid)

for name, rva in RVAS.items():
    actual = base + rva
    # 读前8字节验证
    buf = (ctypes.c_uint8 * 8)()
    n = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(proc, ctypes.c_void_p(actual), buf, 8, ctypes.byref(n))
    if ok:
        hexbytes = " ".join(f"{b:02x}" for b in buf)
        # 验证序言
        expected = EXPECTED_PROLOGS.get(name)
        if expected:
            match = all(buf[i] == expected[i] for i in range(len(expected)))
            status = "OK" if match else "!!"
        else:
            status = "  "
        print(f"[{status}] {name:<16} RVA=0x{rva:07X}  abs=0x{actual:08X}  bytes={hexbytes}")
    else:
        print(f"[!!] {name:<16} RVA=0x{rva:07X}  abs=0x{actual:08X}  READ ERROR")

k32.CloseHandle(proc)

print(f"\n{'='*60}")
print(f"下一步：用以下地址重写 dispatch15.py 中的 DISP_ADDR")
print(f"  DISP_ADDR = ptr(0x{base + RVAS['dispatcher']:08X})  # 当前会话")
print(f"  （或改为动态解析：base + RVA）")
