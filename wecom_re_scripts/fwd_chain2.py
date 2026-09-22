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

TARGETS = [0x8f9e424, 0x8fdc7f2, 0x8fd9204, 0x8f7c9c4]
t_hex = "[" + ",".join(hex(t) for t in TARGETS) + "]"

JS = f"""
var TARGETS={t_hex};
var hits=0;
function ss(p){{try{{if(!p||p.isNull())return"";return p.readCString(200)||""}}catch(e){{return""}}}}
function dA(a){{
    var m=Process.findModuleByAddress(a);
    if(m)return a.toString()+"("+m.name+"+0x"+a.sub(m.base).toString(16)+")";
    return a.toString();
}}
TARGETS.forEach(function(ta){{
    try{{
        Interceptor.attach(ptr(ta),{{onEnter:function(args){{
            hits++;if(hits>100)return;
            var acc=[];
            try{{acc=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,25).map(dA);}}catch(e){{}}
            var a0=ss(args[0]),a1=ss(args[1]),a2=ss(args[2]),a3=ss(args[3]);
            send({{t:"h",addr:"0x"+ptr(ta).toString().replace("0x",""),
                   acc:acc,a0:a0,a1:a1,a2:a2,a3:a3,tid:this.threadId}});
        }}}});
    }}catch(e){{}}
}});
send({{t:"r"}});
"""

results=[]
def cb(m,d):
    if m.get("type")!="send": return
    p=m["payload"]
    if p.get("t")=="r":
        print("="*50,flush=True)
        print(">>> HOOK READY — 请现在立刻转发！ <<<",flush=True)
        print("="*50,flush=True)
    elif p.get("t")=="h":
        results.append(p)
        print(f"\n[HIT #{len(results)}] addr={p['addr']} tid={p['tid']}",flush=True)
        print(f"  args: {p.get('a0','')[:50]!r} | {p.get('a1','')[:30]!r} | {p.get('a2','')[:30]!r}",flush=True)
        print(f"  ACCURATE bt:",flush=True)
        for a in p.get("acc",[]): print(f"    {a}",flush=True)

sc=sess.create_script(JS)
sc.on("message",cb)
sc.load()
time.sleep(300)

ts=datetime.now().strftime("%Y%m%d_%H%M%S")
out=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")/f"fwd_chain_{ts}.json"
out.write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"DONE hits={len(results)} -> {out}",flush=True)
