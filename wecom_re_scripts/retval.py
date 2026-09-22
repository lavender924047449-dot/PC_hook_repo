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
print(f"PID={pid}")
sess = frida.get_local_device().attach(pid)

JS = """
var T=ptr(0x1023810),HIT=0,ARMED=0,EVS=[];
function tryRead(p){
    if(!p||p.isNull())return"";
    // 尝试 char*
    try{var s=p.readCString(400);if(s&&s.indexOf('into')>=0)return"[C]:"+s.slice(0,200);}catch(e){}
    // 尝试 wchar*
    try{var w=p.readUtf16String(200);if(w&&w.indexOf('into')>=0)return"[W]:"+w.slice(0,200);}catch(e){}
    // 尝试偏移8 (std::string data ptr)
    try{var sp=p.add(8).readPointer();var ss=sp.readCString(400);if(ss&&ss.indexOf('into')>=0)return"[S8]:"+ss.slice(0,200);}catch(e){}
    // 尝试偏移4 (std::string data ptr 32bit)  
    try{var sp4=p.add(4).readPointer();var ss4=sp4.readCString(400);if(ss4&&ss4.indexOf('into')>=0)return"[S4]:"+ss4.slice(0,200);}catch(e){}
    return"";
}
Interceptor.attach(T,{
    onEnter:function(args){
        if(!ARMED)return;
        this._a0=args[0];
        var tmpl="";try{tmpl=args[0].readCString(100)||"";}catch(e){}
        this._isInsert=tmpl.match(/^(INSERT|REPLACE|insert|replace)/)?true:false;
        this._tmpl=tmpl.slice(0,60);
    },
    onLeave:function(retval){
        if(!ARMED||!this._isInsert)return;
        HIT++;
        var ret=tryRead(retval);
        // 也尝试读 retval 本身
        var direct="";
        try{direct=retval.readCString(400)||"";}catch(e){}
        EVS.push({n:HIT,tmpl:this._tmpl,ret:ret,direct:direct.slice(0,300)});
        send({t:"i",n:HIT,tmpl:this._tmpl,ret:ret,direct:direct.slice(0,200)});
    }
});
recv('arm',function(){ARMED=1;send({t:'armed'});});
recv('disarm',function(){ARMED=0;send({t:'disarmed',evs:EVS});});
send({t:"r"});
"""

evs=[]
def cb(m,d):
    if m.get("type")!="send": return
    p=m["payload"]
    t=p.get("t","")
    if t=="r":
        print(">>> HOOK READY <<<",flush=True)
    elif t=="armed":
        print(f"[{datetime.now():%H:%M:%S}] ★ 开始录制返回值！立刻执行转发！",flush=True)
    elif t=="i":
        ret=p.get("ret","")
        direct=p.get("direct","")
        print(f"  #{p['n']} tmpl={p['tmpl'][:40]!r}",flush=True)
        if ret: print(f"       ret={ret[:120]!r}",flush=True)
        if direct and 'into' in direct.lower(): print(f"       direct={direct[:120]!r}",flush=True)
    elif t=="disarmed":
        evs.extend(p.get("evs",[]))
        print(f"停止，共{len(evs)}条",flush=True)

sc=sess.create_script(JS)
sc.on("message",cb)
sc.load()
time.sleep(3)
sc.post({"type":"arm"})
time.sleep(30)
sc.post({"type":"disarm"})
time.sleep(3)
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
out=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")/f"retval_{ts}.json"
out.write_text(json.dumps(evs,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"DONE -> {out}",flush=True)
