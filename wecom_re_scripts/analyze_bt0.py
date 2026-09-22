import frida, subprocess, time, sys
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
// 1. 找 0x394a050f 属于哪个模块
var addr = ptr(0x394a050f);
var mods = Process.enumerateModules();
var found = null;
for(var i=0;i<mods.length;i++){
    var m = mods[i];
    var s = m.base, e = s.add(m.size);
    if(addr.compare(s)>=0 && addr.compare(e)<0){
        found = m;
        break;
    }
}
if(found){
    var rva = addr.sub(found.base);
    send({type:'mod', name:found.name, base:found.base.toString(), rva:rva.toString(), path:found.path});
} else {
    send({type:'notfound', addr:'0x394a050f'});
}

// 2. 对 0x394a050f 做精确 hook，捕获完整 backtrace
var TARGET = ptr(0x394a050f);
Interceptor.attach(TARGET, {onEnter:function(args){
    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,20).map(function(a){return a.toString();});
    var fuzzy = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0,20).map(function(a){return a.toString();});
    // 读寄存器
    var ctx = this.context;
    send({type:'hit', eax:ctx.eax.toString(), ecx:ctx.ecx.toString(), edx:ctx.edx.toString(),
          esp:ctx.esp.toString(), ebp:ctx.ebp.toString(),
          bt:bt, fuzzy:fuzzy, tid:this.threadId});
}});
send({type:'ready'});
"""

results = []
done = [False]

def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    t = p.get("type","")
    if t == "ready":
        print(">>> HOOK READY - 请再次执行转发操作 <<<")
    elif t == "mod":
        print(f"模块: {p['name']} base={p['base']} RVA={p['rva']} path={p['path']}")
    elif t == "notfound":
        print(f"地址 {p['addr']} 不属于任何已知模块")
    elif t == "hit":
        print(f"\n=== HIT ===")
        print(f"  寄存器: eax={p['eax']} ecx={p['ecx']} edx={p['edx']}")
        print(f"  ACCURATE backtrace:")
        for a in p.get("bt",[]): print(f"    {a}")
        print(f"  FUZZY backtrace:")
        for a in p.get("fuzzy",[]): print(f"    {a}")
        results.append(p)
        done[0] = True

sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(90)
print(f"DONE hits={len(results)}")
