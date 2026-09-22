import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

def find_main_pid():
    result = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, encoding="gbk", errors="replace"
    )
    import csv, io
    best_pid, best_mem = None, 0
    for row in csv.reader(io.StringIO(result.stdout)):
        if len(row) < 5: continue
        try:
            pid = int(row[1].strip('"'))
            mem = int(row[4].strip('"').replace(',','').replace(' K','').strip())
            if mem > best_mem:
                best_mem, best_pid = mem, pid
        except: pass
    return best_pid, best_mem

# 等企微主进程出现（内存 > 200MB）
print("等待企微主进程（>200MB）...", flush=True)
for _ in range(60):
    pid, mem = find_main_pid()
    if pid and mem > 200*1024:
        print(f"主进程 PID={pid} 内存={mem//1024}MB", flush=True)
        break
    print(f"  等待中... 当前最大={mem//1024}MB", flush=True)
    time.sleep(3)
else:
    print("超时，未等到主进程")
    sys.exit(1)

sess = frida.get_local_device().attach(pid)

JS = """
// Hook WSASend 抓发送数据 (网络层)
var ws2 = Module.load('ws2_32.dll');
var WSASend = Module.getExportByName('ws2_32.dll', 'WSASend');
send({t:'info', WSASend: WSASend.toString()});

var HIT=0, ARMED=0, EVS=[];
Interceptor.attach(WSASend, {
    onEnter: function(args) {
        if(!ARMED) return;
        // SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount
        var s = args[0].toInt32();
        var lpBuffers = args[1];
        var count = args[2].toInt32();
        if(count <= 0 || count > 100) return;
        HIT++;
        if(HIT > 2000) return;
        var chunks = [];
        var total_len = 0;
        for(var i=0; i<Math.min(count,3); i++){
            try{
                var buf = lpBuffers.add(i*8);  // WSABUF = {len,buf} = 8 bytes
                var blen = buf.readU32();
                var bptr = buf.add(4).readPointer();
                if(blen > 0 && blen < 65536 && !bptr.isNull()){
                    total_len += blen;
                    var raw = new Uint8Array(bptr.readByteArray(Math.min(blen, 512)));
                    // 尝试读成字符串
                    var str = '';
                    for(var j=0;j<Math.min(raw.length,200);j++){
                        var c=raw[j];
                        str += (c>=32&&c<127)?String.fromCharCode(c):'?';
                    }
                    chunks.push({len:blen, hex:Array.from(raw.slice(0,16)).map(function(b){return b.toString(16).padStart(2,'0')}).join(' '), str:str});
                }
            }catch(e){}
        }
        if(chunks.length>0 && total_len > 20){
            send({t:'send', n:HIT, s:s, chunks:chunks, ts:Date.now()});
        }
    }
});
recv('arm',function(){ARMED=1;send({t:'armed'});});
recv('disarm',function(){ARMED=0;send({t:'disarmed',count:HIT,evs:EVS});});
send({t:'r'});
"""

evs=[]
def cb(m,d):
    if m.get("type")!="send": return
    p=m["payload"]
    t=p.get("t","")
    if t=="info":
        print(f"WSASend @ {p['WSASend']}", flush=True)
    elif t=="r":
        print("HOOK READY", flush=True)
    elif t=="armed":
        print(f"[{datetime.now():%H:%M:%S}] ARM! 立刻执行转发！", flush=True)
    elif t=="send":
        for c in p.get("chunks",[]):
            s = c.get("str","")
            if any(kw in s for kw in ["forward","Forward","POST","CGI","mmwx","/cgi-bin","wework"]):
                print(f"[FORWARD?] #{p['n']} len={c['len']} hex={c['hex']}", flush=True)
                print(f"           str={s[:150]!r}", flush=True)
                evs.append(p)
            elif len(s.strip()) > 5:
                # 打印任意非空发送
                print(f"  send #{p['n']} len={c['len']} {s[:60]!r}", flush=True)
    elif t=="disarmed":
        print(f"DONE hits={p['count']}", flush=True)

sc=sess.create_script(JS)
sc.on("message",cb)
sc.load()
time.sleep(3)
sc.post({"type":"arm"})
time.sleep(60)  # 60秒窗口
sc.post({"type":"disarm"})
time.sleep(3)
ts=datetime.now().strftime("%Y%m%d_%H%M%S")
out=Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")/f"net_fwd_{ts}.json"
out.write_text(json.dumps(evs,ensure_ascii=False,indent=2),encoding="utf-8")
print(f"SAVED -> {out}", flush=True)
sc.unload(); sess.detach()
