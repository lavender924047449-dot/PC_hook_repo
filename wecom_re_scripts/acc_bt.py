import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def gpid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l:
            return int(l.strip().split()[-1])

pid = gpid()
print(f"PID={pid}", flush=True)
sess = frida.get_local_device().attach(pid)

# 极简 hook：只在 ACCURATE backtrace，只捕获 INSERT
# 不做 FUZZY，不做多余读取，减少崩溃风险
JS = """
var T=ptr(0x1023810),HIT=0,ARMED=0,EVS=[];
function ss(p){try{if(!p||p.isNull())return'';var s=p.readCString(100);return s?s.slice(0,80):''}catch(e){return''}}
Interceptor.attach(T,{
    onEnter:function(args){
        if(!ARMED)return;
        var s0=ss(args[0]);
        if(!s0.match(/^(INSERT|REPLACE)/i))return;
        HIT++;if(HIT>500)return;
        var acc=[];
        try{acc=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,20).map(function(a){
            var m=Process.findModuleByAddress(a);
            return a.toString()+(m?'('+m.name+'+0x'+a.sub(m.base).toString(16)+')':'');
        });}catch(e){}
        EVS.push({n:HIT,s0:s0,acc:acc,tid:this.threadId});
        send({t:'i',n:HIT,s0:s0.slice(0,60),acc:acc});
    }
});
recv('arm',function(){ARMED=1;send({t:'armed'});});
recv('disarm',function(){ARMED=0;send({t:'done',evs:EVS});});
send({t:'r'});
"""

evs=[]
def cb(m, d):
    if m.get("type")!="send": return
    p=m["payload"]
    t=p.get("t","")
    if t=="r":
        print("HOOK READY",flush=True)
    elif t=="armed":
        print(f"[{datetime.now():%H:%M:%S}] ARM! 立刻转发！",flush=True)
    elif t=="i":
        print(f"  #{p['n']} {p['s0']!r}",flush=True)
        for a in p.get("acc",[])[:8]: print(f"    {a}",flush=True)
    elif t=="done":
        evs.extend(p.get("evs",[]))
        print(f"DISARMED total={len(evs)}",flush=True)

sc=sess.create_script(JS)
sc.on("message",cb)
sc.load()
time.sleep(3)
sc.post({"type":"arm"})
time.sleep(30)
sc.post({"type":"disarm"})
time.sleep(3)
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
out=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")/f"acc_bt_{ts}.json"
out.write_text(json.dumps(evs,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"DONE -> {out}",flush=True)
sc.unload()
sess.detach()
