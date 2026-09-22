import sys,time,json,subprocess,frida
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8",errors="replace",line_buffering=True)
OUT=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
def gpid():
    o=subprocess.run(["netstat","-ano"],capture_output=True,text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l: return int(l.strip().split()[-1])
pid=gpid()
print(f"PID={pid}")
BASELINE={0x9052c51,0x3130178,0x8ff5bd5,0x90af838,0x90b41d2,0x90958de,0x90cc7ed,0x901b087,0x90a9f91,0x90cc49a,0x90d17b2,0x90febaf}
bl="["+",".join(f"0x{x:x}" for x in sorted(BASELINE))+"]"
JS=f"""
var T=ptr(0x1023810),HIT=0,BL={bl},BS={{}};
BL.forEach(function(a){{BS[a]=1;}});
function ss(p){{try{{if(!p||p.isNull())return"";var s=p.readCString(300);return s?s.slice(0,250):""}}catch(e){{return""}}}}
Interceptor.attach(T,{{onEnter:function(args){{
    HIT++;if(HIT>500000)return;
    var st=[];for(var i=0;i<6;i++)st.push(ss(args[i]));
    if(!st.some(function(s){{return s.match(/^(INSERT|REPLACE|insert|replace)/)}}))return;
    var bt=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,8).map(function(a){{return a.toString();}});
    var bt0=bt.length>0?parseInt(bt[0],16):0;
    send({{t:"i",n:HIT,st:st,bt:bt,bt0:bt0,new:!BS[bt0],tid:this.threadId}});
}}}});
send({{t:"r"}});
"""
evs=[];news=[]
def cb(m,d):
    if m.get("type")!="send":return
    p=m["payload"]
    if p.get("t")=="r":
        print(">>> HOOK READY - 请在企微执行: 右键消息->转发->选人->发送 <<<")
    elif p.get("t")=="i":
        evs.append(p)
        sql=next((s for s in p.get("st",[]) if s),"")
        mk="NEW" if p.get("new") else "   "
        print(f"[{mk}] #{p['n']} 0x{p['bt0']:x} | {sql[:80]!r}")
        if p.get("new"):news.append(p)
sess=frida.get_local_device().attach(pid)
sc=sess.create_script(JS);sc.on("message",cb);sc.load()
try:time.sleep(600)
except KeyboardInterrupt:pass
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
f=OUT/f"hooknow_{ts}.json"
f.write_text(json.dumps(evs,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"DONE INSERT={len(evs)} NEW={len(news)} -> {f}")
