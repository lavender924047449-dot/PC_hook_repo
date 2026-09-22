import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def gpid():
    for _ in range(60):
        o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
        for l in o.splitlines():
            if ":9882" in l and "LISTENING" in l:
                return int(l.strip().split()[-1])
        time.sleep(2)
    return None

print("等待企微启动...", flush=True)
pid = gpid()
if not pid:
    print("超时，未找到企微"); sys.exit(1)
print(f"PID={pid}", flush=True)

# 等企微稳定 20s
time.sleep(20)
print("企微已稳定，hook 准备中...", flush=True)
sess = frida.get_local_device().attach(pid)

# 极简 hook：无 backtrace，只记录 SQL args（表名+列名）
JS = """
var T=ptr(0x1023810),HIT=0,ARMED=0,EVS=[];
function ss(p){try{if(!p||p.isNull())return"";return p.readCString(400)||""}catch(e){return""}}
Interceptor.attach(T,{onEnter:function(args){
    if(!ARMED)return;
    HIT++;
    var s0=ss(args[0]),s1=ss(args[1]),s2=ss(args[2]),s3=ss(args[3]),s4=ss(args[4]),s5=ss(args[5]);
    if(!s0.match(/^(INSERT|REPLACE|insert|replace)/))return;
    EVS.push({n:HIT,s0:s0,s1:s1,s2:s2,s3:s3,s4:s4,s5:s5,tid:this.threadId,ts:Date.now()});
    send({t:"i",n:HIT,s0:s0.slice(0,80),s1:s1.slice(0,40),s2:s2.slice(0,40)});
}});
recv('arm',function(){ARMED=1;send({t:'armed'});});
recv('disarm',function(){ARMED=0;send({t:'disarmed',count:EVS.length,evs:EVS});});
send({t:"r"});
"""

all_evs = []
def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    t = p.get("t","")
    if t == "r":
        print(">>> HOOK READY <<<", flush=True)
        print("等待 arm 信号...", flush=True)
    elif t == "armed":
        print(f"[{datetime.now():%H:%M:%S}] ★ 开始录制！立刻执行转发！", flush=True)
    elif t == "i":
        s0r = repr(p['s0'][:60])
        s1r = repr(p.get('s1','')[:20])
        print(f"  SQL#{p['n']}: {s0r} tbl={s1r}", flush=True)
    elif t == "disarmed":
        all_evs.extend(p.get("evs",[]))
        print(f"[{datetime.now():%H:%M:%S}] 停止录制 共{p['count']}条", flush=True)

sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(3)

# arm
sc.post({"type": "arm"})
time.sleep(25)  # 25s 录制窗口
sc.post({"type": "disarm"})
time.sleep(3)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re") / f"sql_record_{ts}.json"
out.write_text(json.dumps(all_evs, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"DONE -> {out}", flush=True)
