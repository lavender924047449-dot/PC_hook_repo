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

# 对 4 个转发专属 bt0 做精确 hook，获取完整调用链
TARGETS = [0x8f9e424, 0x8fdc7f2, 0x8fd9204, 0x8f7c9c4]
t_hex = "[" + ",".join(hex(t) for t in TARGETS) + "]"

JS = f"""
var TARGETS={t_hex};
var hits=0;
function ss(p){{try{{if(!p||p.isNull())return"";return p.readCString(200)||""}}catch(e){{return""}}}}
function dumpAddr(a){{
    var m=Process.findModuleByAddress(a);
    if(m)return a+" ("+m.name+"+0x"+a.sub(m.base).toString(16)+")";
    return a.toString();
}}
TARGETS.forEach(function(taddr){{
    try{{
        Interceptor.attach(ptr(taddr),{{onEnter:function(args){{
            hits++;if(hits>200)return;
            var accurate=[];
            try{{accurate=Thread.backtrace(this.context,Backtracer.ACCURATE).slice(0,20).map(dumpAddr);}}catch(e){{}}
            var fuzzy=Thread.backtrace(this.context,Backtracer.FUZZY).slice(0,10).map(dumpAddr);
            var arg0=ss(args[0]),arg1=ss(args[1]),arg2=ss(args[2]);
            send({{t:"h",addr:ptr(taddr).toString(),tid:this.threadId,
                   accurate:accurate,fuzzy:fuzzy,
                   arg0:arg0,arg1:arg1,arg2:arg2}});
        }}}});
        send({{t:"ok",addr:ptr(taddr).toString()}});
    }}catch(e){{send({{t:"err",addr:ptr(taddr).toString(),e:e.toString()}});}}
}});
send({{t:"r"}});
"""

results = []
def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    t = p.get("t","")
    if t == "r":
        print(">>> HOOK READY - 请再次执行转发！ <<<")
    elif t == "ok":
        print(f"  Hooked {p['addr']}")
    elif t == "err":
        print(f"  FAIL {p['addr']}: {p['e']}")
    elif t == "h":
        results.append(p)
        print(f"\n{'='*60}")
        print(f"HIT at {p['addr']}  tid={p['tid']}")
        print(f"  args: {p.get('arg0','')[:60]!r} | {p.get('arg1','')[:40]!r} | {p.get('arg2','')[:40]!r}")
        print(f"  ACCURATE bt ({len(p['accurate'])} frames):")
        for a in p['accurate']: print(f"    {a}")
        print(f"  FUZZY bt ({len(p['fuzzy'])} frames):")
        for a in p['fuzzy']: print(f"    {a}")

sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(180)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re") / f"fwd_chain_{ts}.json"
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\nDONE hits={len(results)} -> {out}")
