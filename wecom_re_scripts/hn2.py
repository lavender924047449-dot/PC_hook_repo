import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

def gpid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l:
            return int(l.strip().split()[-1])

pid = gpid()
print(f"PID={pid}")
dev = frida.get_local_device()

# 先获取新基址
sess = dev.attach(pid)
sc0 = sess.create_script("var m=Process.getModuleByName('WXWork.exe');send({base:m.base.toString(),sz:m.size});")
base_addr = [None]
def cb0(m, d):
    if m.get("type") == "send":
        base_addr[0] = int(m["payload"]["base"], 16)
        print(f"  base=0x{base_addr[0]:X} size={m['payload']['sz']}")
sc0.on("message", cb0)
sc0.load()
time.sleep(2)
sc0.unload()

b = base_addr[0]
RVA = 0x2A3810
hook_addr = b + RVA
print(f"  hook=0x{hook_addr:X} (base=0x{b:X} + RVA=0x{RVA:X})")

# 验证字节
JS_VERIFY = f"""
var T=ptr(0x{hook_addr:X});
var raw=new Uint8Array(T.readByteArray(6));
send({{bytes:[raw[0],raw[1],raw[2],raw[3],raw[4],raw[5]]}});
"""
sc1 = sess.create_script(JS_VERIFY)
vbytes = [None]
def cb1(m, d):
    if m.get("type") == "send":
        b6 = m["payload"]["bytes"]
        print(f"  bytes={[hex(x) for x in b6]}")
        vbytes[0] = b6
sc1.on("message", cb1)
sc1.load()
time.sleep(2)
sc1.unload()

# Hook: 60秒捕获所有 INSERT
JS = f"""
var T=ptr(0x{hook_addr:X}),HIT=0;
function ss(p){{try{{if(!p||p.isNull())return"";var s=p.readCString(300);return s?s.slice(0,250):""}}catch(e){{return""}}}}
Interceptor.attach(T,{{onEnter:function(args){{
    HIT++;if(HIT>50000)return;
    var st=[];for(var i=0;i<6;i++)st.push(ss(args[i]));
    if(!st.some(function(s){{return s.match(/^(INSERT|REPLACE|insert|replace)/)}}))return;
    var bt=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,8).map(function(a){{return a.toString();}});
    var bt0=bt.length>0?parseInt(bt[0],16):0;
    send({{t:"i",n:HIT,st:st,bt:bt,bt0:bt0,tid:this.threadId}});
}}}});
send({{t:"r"}});
"""

evs = []
def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    if p.get("t") == "r":
        print(">>> HOOK READY - 请立刻在企微执行转发！ <<<")
    elif p.get("t") == "i":
        evs.append(p)
        sql = next((s for s in p.get("st",[]) if s), "")
        print(f"INSERT #{p['n']} bt0=0x{p['bt0']:x} | {sql[:80]!r}")

sc2 = sess.create_script(JS)
sc2.on("message", cb)
sc2.load()
try:
    time.sleep(120)
except KeyboardInterrupt:
    pass

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
f = OUT / f"hooknow2_{ts}.json"
f.write_text(json.dumps(evs, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"DONE INSERT={len(evs)} -> {f}")
