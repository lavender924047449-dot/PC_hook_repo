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

# 捕获所有 INSERT，不做基线过滤，只看时间窗口
JS = """
var T=ptr(0x1023810),HIT=0,ARMED=0;
function ss(p){try{if(!p||p.isNull())return"";return p.readCString(200)||""}catch(e){return""}}
function dA(a){var m=Process.findModuleByAddress(a);if(m)return a.toString()+"("+m.name+"+0x"+a.sub(m.base).toString(16)+")";return a.toString();}
Interceptor.attach(T,{onEnter:function(args){
    if(!ARMED)return;
    HIT++;if(HIT>5000)return;
    var st=[];for(var i=0;i<6;i++)st.push(ss(args[i]));
    if(!st.some(function(s){return s.match(/^(INSERT|REPLACE|insert|replace)/)}))return;
    var bt=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,14).map(dA);
    var bt0=bt.length>0?bt[0]:"?";
    send({t:"i",n:HIT,st:st,bt:bt,bt0:bt0,tid:this.threadId,ts:Date.now()});
}});
recv('arm',function(v){ARMED=1;send({t:'armed'});});
send({t:"r"});
"""

window_hits = []
armed = [False]

def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    t = p.get("t","")
    if t == "r":
        print("\n准备就绪，输入指令后脚本自动开窗口...")
        print(">>> 请在 10 秒内完成转发操作 <<<", flush=True)
    elif t == "armed":
        armed[0] = True
        print(f"[{datetime.now():%H:%M:%S}] ★ 采集窗口已开启！立刻执行转发！", flush=True)
    elif t == "i":
        window_hits.append(p)
        sql = next((s for s in p.get("st",[]) if s),"")
        print(f"  +{p['n']} bt0={p['bt0'].split('(')[0]}  {sql[:60]!r}", flush=True)

sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(3)  # 等 hook 就绪

# 发送 arm 信号，开始记录
sc.post({"type": "arm"})
time.sleep(30)  # 等 30 秒

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re") / f"fwd_window_{ts}.json"
out.write_text(json.dumps(window_hits, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\nDONE total_in_window={len(window_hits)} -> {out}", flush=True)
