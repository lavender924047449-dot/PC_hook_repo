import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def find_main_pid():
    """找内存最大的 WXWork.exe 进程（真正的主进程）"""
    result = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, encoding="gbk", errors="replace"
    )
    best_pid, best_mem = None, 0
    import csv, io
    for row in csv.reader(io.StringIO(result.stdout)):
        if len(row) < 5: continue
        try:
            pid = int(row[1].strip('"'))
            mem_str = row[4].strip('"').replace(',','').replace(' K','').strip()
            mem_kb = int(mem_str)
            print(f"  WXWork PID={pid} mem={mem_kb}KB")
            if mem_kb > best_mem:
                best_mem = mem_kb
                best_pid = pid
        except: pass
    return best_pid, best_mem

print("=== 当前所有 WXWork.exe 进程 ===")
pid, mem_kb = find_main_pid()
if not pid:
    print("未找到 WXWork.exe！请重启企微后再运行此脚本")
    sys.exit(1)

print(f"\n主进程 PID={pid} 内存={mem_kb//1024}MB")

if mem_kb < 200*1024:
    print("警告：内存 < 200MB，可能还不是主进程，等待企微完全启动...")
    time.sleep(10)
    pid, mem_kb = find_main_pid()
    print(f"再次检测：PID={pid} 内存={mem_kb//1024}MB")

print(f"\n使用 PID={pid} 进行 hook")
