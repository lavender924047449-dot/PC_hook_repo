import frida, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

sess = frida.get_local_device().attach(48796)

JS = r"""
// Hook WSASend 抓转发网络包
var WSASend = Module.getExportByName('ws2_32.dll','WSASend');
var send_packets = [];
var HIT=0, ARMED=0;
Interceptor.attach(WSASend,{
    onEnter:function(args){
        if(!ARMED)return;
        var count=args[2].toInt32();
        if(count<=0||count>50)return;
        HIT++;if(HIT>5000)return;
        var bufs=[];
        for(var i=0;i<Math.min(count,4);i++){
            try{
                var wsabuf=args[1].add(i*8);
                var blen=wsabuf.readU32();
                var bptr=wsabuf.add(4).readPointer();
                if(blen>4&&blen<131072&&!bptr.isNull()){
                    var raw=new Uint8Array(bptr.readByteArray(Math.min(blen,1024)));
                    var hex=Array.from(raw.slice(0,32)).map(function(b){return b.toString(16).padStart(2,'0')}).join(' ');
                    var printable='';
                    for(var j=0;j<Math.min(raw.length,256);j++){
                        var c=raw[j];printable+=(c>=32&&c<127)?String.fromCharCode(c):'.';
                    }
                    bufs.push({len:blen,hex:hex,text:printable});
                }
            }catch(e){}
        }
        if(bufs.length>0){
            send({t:'pkt',n:HIT,bufs:bufs,ts:Date.now()});
        }
    }
});
recv('arm',function(){ARMED=1;send({t:'armed'});});
recv('disarm',function(){ARMED=0;send({t:'done',count:HIT});});
send({t:'r'});
"""

pkts=[]
def cb(m,d):
    if m.get("type")!="send": return
    p=m["payload"]
    t=p.get("t","")
    if t=="r": print("HOOK READY", flush=True)
    elif t=="armed":
        print(f"[{datetime.now():%H:%M:%S}] ARM! 立刻执行转发！60s 内！", flush=True)
    elif t=="pkt":
        for b in p.get("bufs",[]):
            text=b.get("text","")
            # 检测是否与转发相关（含关键词）
            keywords=["forward","Forward","POST","mmwx","cgi","wework","mmapp","msg"]
            is_fwd=any(k.lower() in text.lower() for k in keywords)
            if is_fwd:
                print(f"[FWD?] #{p['n']} len={b['len']}", flush=True)
                print(f"  hex={b['hex']}", flush=True)
                print(f"  txt={text[:200]!r}", flush=True)
                pkts.append(p)
            elif b['len']>100:
                print(f"  pkt#{p['n']} len={b['len']} {text[:80]!r}", flush=True)
    elif t=="done":
        print(f"DONE total_pkts={p['count']}", flush=True)

sc=sess.create_script(JS)
sc.on("message",cb)
sc.load()
time.sleep(2)
sc.post({"type":"arm"})
time.sleep(90)
sc.post({"type":"disarm"})
time.sleep(2)
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
out=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")/f"net_pkts_{ts}.json"
out.write_text(json.dumps(pkts,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"SAVED -> {out}", flush=True)
sc.unload()
sess.detach()
