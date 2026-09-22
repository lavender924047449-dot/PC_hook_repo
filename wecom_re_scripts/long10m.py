import frida, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

sess = frida.get_local_device().attach(48796)
JS = """
var T=ptr(0x1023810),ALL=[],HIT=0;
function ss(p){try{if(!p||p.isNull())return'';return p.readCString(80)||''}catch(e){return''}}
function dA(a){var m=Process.findModuleByAddress(a);if(m)return a.toString()+'('+m.name+'+0x'+a.sub(m.base).toString(16)+')';return a.toString();}
Interceptor.attach(T,{onEnter:function(args){
    HIT++;if(HIT>50000)return;
    var s0=ss(args[0]);
    var isInsert=s0.match(/^(INSERT|REPLACE)/i)?true:false;
    var acc=[];
    if(isInsert){
        try{acc=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,12).map(dA);}catch(e){}
    }
    ALL.push({n:HIT,s0:s0.slice(0,60),isInsert:isInsert,acc:acc,ts:Date.now(),tid:this.threadId});
}});
// 10分钟后自动汇报
setTimeout(function(){send({t:'dump',data:ALL});},600000);
send({t:'r'});
"""

all_evs=[]
def cb(m,d):
    if m.get("type")!="send": return
    p=m["payload"]
    if p.get("t")=="r":
        print(f"[{datetime.now():%H:%M:%S}] HOOK READY — 10分钟窗口已开启", flush=True)
        print("请在企微执行转发，然后告诉我您转发的时间（如：8:55）", flush=True)
    elif p.get("t")=="dump":
        data=p.get("data",[])
        inserts=[e for e in data if e.get("isInsert")]
        all_evs.extend(data)
        print(f"\n[{datetime.now():%H:%M:%S}] 10分钟结束: 总={len(data)} INSERT={len(inserts)}", flush=True)
        # 打印 INSERT 事件
        for e in inserts:
            bt0=e.get("acc",["?"])[0] if e.get("acc") else "?"
            print(f"  INSERT #{e['n']} ts={e['ts']} bt0={bt0}", flush=True)
            print(f"    sql={e['s0']!r}", flush=True)

sc=sess.create_script(JS)
sc.on("message",cb)
sc.load()
time.sleep(650)  # 等 dump
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
out=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")/f"long10m_{ts}.json"
out.write_text(json.dumps(all_evs,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"SAVED -> {out}", flush=True)
sc.unload()
sess.detach()
