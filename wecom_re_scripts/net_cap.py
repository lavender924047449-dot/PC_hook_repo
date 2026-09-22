import frida, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

sess = frida.get_local_device().attach(48796)

JS = """
var WSASEND=ptr(0x7581dff0);
var HIT=0,ARMED=0,PKTS=[];
Interceptor.attach(WSASEND,{onEnter:function(args){
    if(!ARMED)return;
    HIT++;if(HIT>2000)return;
    var count=args[2].toInt32();
    if(count<=0||count>50)return;
    var bufs=[];
    for(var i=0;i<Math.min(count,3);i++){
        try{
            var wsabuf=args[1].add(i*8);
            var blen=wsabuf.readU32();
            var bptr=wsabuf.add(4).readPointer();
            if(blen>0&&blen<131072&&!bptr.isNull()){
                var raw=new Uint8Array(bptr.readByteArray(Math.min(blen,512)));
                var hex=Array.from(raw).map(function(b){return b.toString(16).padStart(2,'0')}).join('');
                bufs.push({len:blen,hex:hex});
            }
        }catch(e){}
    }
    if(bufs.length>0) send({t:'pkt',n:HIT,bufs:bufs,ts:Date.now()});
}});
recv('arm',function(){ARMED=1;send({t:'armed'});});
recv('disarm',function(){ARMED=0;send({t:'done',pkts:PKTS});});
send({t:'r'});
"""

pkts=[]
def cb(m,d):
    if m.get("type")!="send": return
    p=m["payload"]
    t=p.get("t","")
    if t=="r": print("HOOK READY", flush=True)
    elif t=="armed": print(f"[{datetime.now():%H:%M:%S}] ★ 开始！立刻执行转发！", flush=True)
    elif t=="pkt":
        for b in p.get("bufs",[]):
            pkts.append({"n":p["n"],"len":b["len"],"hex":b["hex"],"ts":p["ts"]})
            h=b["hex"]
            # 尝试解码为字符串，找关键词
            txt="".join(chr(int(h[i:i+2],16)) if 32<=int(h[i:i+2],16)<127 else "." for i in range(0,min(len(h),160),2))
            print(f"  pkt#{p['n']} len={b['len']} {txt[:80]!r}", flush=True)
    elif t=="done": print(f"DONE pkts={len(pkts)}", flush=True)

sc=sess.create_script(JS)
sc.on("message",cb)
sc.load()
time.sleep(2)
sc.post({"type":"arm"})
time.sleep(90)
sc.post({"type":"disarm"})
time.sleep(3)
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
out=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")/f"net_cap_{ts}.json"
out.write_text(json.dumps(pkts,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"SAVED {len(pkts)} pkts -> {out}", flush=True)
sc.unload()
sess.detach()
