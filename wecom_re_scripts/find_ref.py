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

JS = r"""
var wxwork = Process.getModuleByName('WXWork.exe');
var base = wxwork.base;
var size = wxwork.size;

// 目标：在全模块找对 0xe21f40d 的引用（4字节小端）
var TARGET = 0xe21f40d;
var b0=(TARGET&0xff).toString(16).padStart(2,'0');
var b1=((TARGET>>8)&0xff).toString(16).padStart(2,'0');
var b2=((TARGET>>16)&0xff).toString(16).padStart(2,'0');
var b3=((TARGET>>24)&0xff).toString(16).padStart(2,'0');
var pat = b0+' '+b1+' '+b2+' '+b3;
send({t:'info',pat:pat,size:size});

var CHUNK=16*1024*1024;
var found=[];
for(var off=0;off<size;off+=CHUNK){
    var sz=Math.min(CHUNK,size-off);
    try{
        var hits=Memory.scanSync(base.add(off),sz,pat);
        for(var j=0;j<hits.length;j++){
            var addr=hits[j].address;
            var rva=addr.sub(base);
            // 读周围16字节
            var ctx="";
            try{var raw=new Uint8Array(addr.sub(8).readByteArray(24));
                ctx=Array.from(raw).map(function(b){return b.toString(16).padStart(2,'0')}).join(' ');}catch(e){}
            found.push({addr:addr.toString(),rva:rva.toString(),ctx:ctx});
            send({t:'ref',addr:addr.toString(),rva:rva.toString(),ctx:ctx});
        }
    }catch(e){}
}
send({t:'done',count:found.length});
"""

def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    t = p.get("t","")
    if t == "info":
        print(f"扫描全模块 size={p['size']//1024//1024}MB, 搜索pattern={p['pat']}")
    elif t == "ref":
        print(f"  引用: addr={p['addr']} RVA={p['rva']}")
        print(f"        ctx={p['ctx']}")
    elif t == "done":
        print(f"DONE 共{p['count']}处引用")

sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()
time.sleep(180)
sc.unload()
print("脚本完成")
