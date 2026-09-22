import sys, time, json, subprocess, frida
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
OUT.mkdir(parents=True, exist_ok=True)
def get_pid():
    o = subprocess.run(["netstat","-ano"],capture_output=True,text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l:
            return int(l.strip().split()[-1])
pid = get_pid()
print(f"PID={pid}", flush=True)
BASELINE = {0x9052c51,0x3130178,0x8ff5bd5,0x90af838,0x90b41d2,0x90958de,0x90cc7ed,0x901b087,0x90a9f91,0x90cc49a,0x90d17b2,0x90febaf}
bl = "["+",".join(f"0x{x:x}" for x in sorted(BASELINE))+"]"
JS = f"""
var T=ptr(0x1023810),HIT=0,BASELINE={bl},BS={{}};
BASELINE.forEach(function(a){{BS[a]=1;}});
function ss(p){{try{{if(!p||p.isNull())return"";var s=p.readCString(300);return s?s.slice(0,250):""}}catch(e){{return""}}}}
Interceptor.attach(T,{{onEnter:function(args){{
    HIT++;if(HIT>200000)return;
    var strs=[];for(var i=0;i<6;i++)strs.push(ss(args[i]));
    var ins=strs.some(function(s){{return s.match(/^(INSERT|REPLACE|insert|replace)/);}});
    if(!ins)return;
    var bt=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,8).map(function(a){{return a.toString();}});
    var bt0=bt.length>0?parseInt(bt[0],16):0;
    send({{t:"i",n:HIT,strs:strs,bt:bt,bt0:bt0,isNew:!BS[bt0],tid:this.threadId}});
}}}});
send({{t:"r"}});
"""
evs=[]; news=[]
def cb(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="r":
        print("[HOOK READY] 20分钟监听窗口已开启！", flush=True)
        print(">>> 请在企微中: 右键消息->转发->选人->发送 <<<", flush=True)
    elif p.get("t")=="i":
        evs.append(p)
        strs=p.get("strs",[]); bt=p.get("bt",[]); bt0=p.get("bt0",0)
        sql=next((s for s in strs if s),"")
        mk="NEW" if p.get("isNew") else "   "
        print(f"[{mk}] #{p['n']} bt0=0x{bt0:x} | {sql[:80]!r}", flush=True)
        if p.get("isNew"): news.append(p)
sess=frida.get_local_device().attach(pid)
sc=sess.create_script(JS); sc.on("message",cb); sc.load()
try: time.sleep(1200)
except KeyboardInterrupt: pass
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
f=OUT/f"fwd20m_{ts}.json"
f.write_text(json.dumps(evs,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"[*] 完成: INSERT={len(evs)}, NEW={len(news)} -> {f}", flush=True)
