import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASELINE_BT0 = {
    0x9052c51, 0x3130178, 0x8ff5bd5, 0x90af838, 0x90b41d2,
    0x90958de, 0x90cc7ed, 0x901b087, 0x90a9f91, 0x90cc49a,
    0x90d17b2, 0x90febaf, 0x314dc62, 0x8fd26ed, 0x8fc37e5, 0x901b087
}

def gpid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l:
            return int(l.strip().split()[-1])

pid = gpid()
print(f"PID={pid}")
sess = frida.get_local_device().attach(pid)

bl_str = "[" + ",".join(hex(x) for x in BASELINE_BT0) + "]"
JS = f"""
var T=ptr(0x1023810),HIT=0,BL={bl_str},BS={{}};
BL.forEach(function(a){{BS[a]=1;}});
function ss(p){{try{{if(!p||p.isNull())return"";var s=p.readCString(300);return s?s.slice(0,200):""}}catch(e){{return""}}}}
Interceptor.attach(T,{{onEnter:function(args){{
    HIT++;if(HIT>99999)return;
    var st=[];for(var i=0;i<6;i++)st.push(ss(args[i]));
    if(!st.some(function(s){{return s.match(/^(INSERT|REPLACE|insert|replace)/)}}))return;
    var bt=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,16).map(function(a){{return a.toString();}});
    var bt0=bt.length>0?parseInt(bt[0],16):0;
    var isNew=!BS[bt0];
    send({{t:"i",n:HIT,st:st,bt:bt,bt0:bt0,new:isNew,tid:this.threadId}});
}}}});
send({{t:"r"}});
"""

hits = []
def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    if p.get("t") == "r":
        print("=" * 60)
        print(">>> HOOK READY <<<")
        print("请立刻在企微执行消息转发！（3分钟窗口）")
        print("=" * 60)
    elif p.get("t") == "i" and p.get("new"):
        hits.append(p)
        print(f"\n[NEW FORWARD HIT #{len(hits)}]")
        print(f"  SQL: {[s[:80] for s in p['st'] if s][:2]}")
        print(f"  tid={p['tid']}")
        print(f"  FULL BACKTRACE ({len(p['bt'])} frames):")
        for i,a in enumerate(p.get("bt",[])):
            print(f"    [{i}] {a}")

sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(180)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re") / f"fwd_bt_{ts}.json"
out.write_text(json.dumps(hits, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\nDONE hits={len(hits)} -> {out}")
