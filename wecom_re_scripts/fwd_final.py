import frida, subprocess, time, json, sys
from pathlib import Path
from datetime import datetime
sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASELINE_BT0 = {
    0x9052c51, 0x3130178, 0x8ff5bd5, 0x90af838, 0x90b41d2,
    0x90958de, 0x90cc7ed, 0x901b087, 0x90a9f91, 0x90cc49a,
    0x90d17b2, 0x90febaf, 0x314dc62, 0x8fd26ed, 0x8fc37e5
}
# 也排除刚发现的同步操作 bt0（非转发专属）
SYNC_BT0 = {
    0x8f6aaf5, 0x8f777f5, 0x8f778a5, 0x8f77611, 0x8f4a631,
    0x8f4bbb3, 0x900f3f7, 0x91a2a27
}
ALL_BL = BASELINE_BT0 | SYNC_BT0

def gpid():
    o = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for l in o.splitlines():
        if ":9882" in l and "LISTENING" in l:
            return int(l.strip().split()[-1])

pid = gpid()
print(f"PID={pid}", flush=True)
sess = frida.get_local_device().attach(pid)
bl_str = "[" + ",".join(hex(x) for x in ALL_BL) + "]"

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

hits_new = []
last_new_time = [None]
settled = [False]

def cb(m, d):
    if m.get("type") != "send": return
    p = m["payload"]
    if p.get("t") == "r":
        print(">>> HOOK RUNNING - 等待企微同步稳定... <<<", flush=True)
    elif p.get("t") == "i":
        if p.get("new"):
            last_new_time[0] = time.time()
            hits_new.append(p)
            sql = next((s for s in p.get("st",[]) if s), "")
            print(f"[NEW] #{p['n']} bt0=0x{p['bt0']:x} tid={p['tid']} | {sql[:60]!r}", flush=True)

sc = sess.create_script(JS)
sc.on("message", cb)
sc.load()

# 等待同步稳定（30s无新 NEW 事件 = 已稳定）
print("等待同步噪音沉静（30s无新事件后提示）...", flush=True)
stable_window = 30
check_start = time.time()
while time.time() - check_start < 600:  # 最多10分钟
    time.sleep(5)
    elapsed = time.time() - (last_new_time[0] or check_start)
    if elapsed >= stable_window and not settled[0]:
        settled[0] = True
        print(f"\n{'='*60}", flush=True)
        print(f">>> 企微已稳定！请立刻执行消息转发！ <<<", flush=True)
        print(f"{'='*60}\n", flush=True)
    if settled[0]:
        # 稳定后，额外等120s等用户转发
        if time.time() - check_start > 600 - 120:
            break

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re") / f"fwd_final_{ts}.json"
out.write_text(json.dumps(hits_new, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"DONE new_hits={len(hits_new)} -> {out}")
