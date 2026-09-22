import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def find_main_pid():
    result = subprocess.run(
        ["tasklist","/FI","IMAGENAME eq WXWork.exe","/FO","CSV","/NH"],
        capture_output=True, text=True, encoding="gbk", errors="replace"
    )
    import csv, io
    best_pid, best_mem = None, 0
    for row in csv.reader(io.StringIO(result.stdout)):
        if len(row) < 5: continue
        try:
            pid = int(row[1].strip('"'))
            mem = int(row[4].strip('"').replace(',','').replace(' K','').strip())
            if mem > best_mem: best_mem, best_pid = mem, pid
        except: pass
    return best_pid, best_mem

pid, mem = find_main_pid()
print(f"最大进程 PID={pid} 内存={mem//1024}MB", flush=True)
if not pid:
    print("未找到 WXWork.exe"); sys.exit(1)

print(f"Attach PID={pid}...", flush=True)
sess = frida.get_local_device().attach(pid)

# 先验证 0x1023810 是否还有效
VERIFY_JS = """
var bytes = ptr(0x1023810).readByteArray(6);
var raw = new Uint8Array(bytes);
var hex = Array.from(raw).map(function(b){return b.toString(16).padStart(2,'0')}).join(' ');
// 统计 10s 内的调用次数
var cnt=0;
Interceptor.attach(ptr(0x1023810),{onEnter:function(){cnt++;}});
var t=Date.now();
while(Date.now()-t<5000){}
send({hex:hex,cnt:cnt});
"""
results = [None]
def cb0(m,d):
    if m.get("type")=="send": results[0]=m["payload"]
sc0=sess.create_script(VERIFY_JS)
sc0.on("message",cb0)
sc0.load()
time.sleep(7)
r = results[0]
if r:
    print(f"0x1023810: bytes={r.get('hex','')} calls_in_5s={r.get('cnt',0)}", flush=True)
else:
    print("验证失败", flush=True)
sc0.unload()
