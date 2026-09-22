import argparse
import frida
import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
TS = datetime.now().strftime("%Y%m%d_%H%M%S")

CANDIDATES = {
    "cfg_send_voice_text": 0x57C9062,
    "asr_key_path": 0x049280,
    "voice2text_auto": 0x0F1F9A0,
    "offline_update_cmd": 0x0F224F0,
    "aes_path_a": 0x81E47F2,
    "aes_path_b": 0x81E6673,
    "aes_path_c": 0x83C57E2,
}

JS_TMPL = r"""
'use strict';
var mod = Process.getModuleByName('WXWork.exe');
var BASE = mod.base;
var CANDS = __CANDS__;
var PRESEND = BASE.add(0x919ffb2);
var gate = {};

function u32(p){ try{return p.toUInt32()>>>0;}catch(e){return 0;} }
function hx(ab){
  if(!ab) return '';
  var a=new Uint8Array(ab), s='';
  for(var i=0;i<a.length;i++) s += ('0'+a[i].toString(16)).slice(-2);
  return s;
}
function desc(p){
  try{
    var v=u32(p), b=u32(BASE);
    if(v>=b && v<b+mod.size) return 'wx+0x'+(v-b).toString(16);
    return '0x'+v.toString(16);
  }catch(e){ return '?'; }
}
function bt(ctx){
  try{
    return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0,8).map(desc);
  }catch(e){ return []; }
}

Interceptor.attach(PRESEND, {
  onEnter: function(){
    gate[this.threadId] = (gate[this.threadId]||0)+1;
    send({t:'gate',ev:'enter',tid:this.threadId,lv:gate[this.threadId]});
  },
  onLeave: function(){
    var n=(gate[this.threadId]||1)-1;
    if(n<=0) delete gate[this.threadId]; else gate[this.threadId]=n;
    send({t:'gate',ev:'leave',tid:this.threadId,lv:n});
  }
});

Object.keys(CANDS).forEach(function(name){
  var rva = CANDS[name];
  var fn = BASE.add(rva);
  try{
    Interceptor.attach(fn, {
      onEnter: function(args){
        var inGate = !!gate[this.threadId];
        var ecx = this.context.ecx;
        var a0 = args[0], a1 = args[1];
        var p = {
          t:'hit',
          name:name,
          rva:'0x'+rva.toString(16),
          tid:this.threadId,
          in_presend:inGate,
          ecx: ecx ? ecx.toString() : '0',
          a0:  a0  ? a0.toString()  : '0',
          a1:  a1  ? a1.toString()  : '0',
          bt: bt(this.context)
        };
        // lightweight content sniff (avoid heavy memory exceptions)
        try{
          var b0 = ptr(a0).readByteArray(64);
          p.a0hex = hx(b0);
        }catch(e){}
        try{
          var be = ptr(ecx).readByteArray(64);
          p.ecxhex = hx(be);
        }catch(e){}
        send(p);
      }
    });
    send({t:'hook',name:name,rva:'0x'+rva.toString(16),ok:true});
  }catch(e){
    send({t:'hook',name:name,rva:'0x'+rva.toString(16),ok:false,err:String(e)});
  }
});
"""


events = []
bt_count = Counter()
hit_count = Counter()
gate_count = 0


def get_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("no WXWork pid on :9882")


def on_message(msg, _data):
    global gate_count
    if msg.get("type") != "send":
        print(msg, flush=True)
        return
    p = msg["payload"]
    events.append(p)
    t = p.get("t")
    if t == "hook":
        print(f"[HOOK] {p.get('name')} {p.get('rva')} ok={p.get('ok')} {p.get('err','')}", flush=True)
    elif t == "gate":
        gate_count += 1
        if p.get("ev") == "enter":
            print(f"[PreSend] ENTER tid={p.get('tid')} lv={p.get('lv')}", flush=True)
    elif t == "hit":
        name = p.get("name")
        hit_count[name] += 1
        tag = "IN" if p.get("in_presend") else "OUT"
        print(f"[HIT:{tag}] {name} #{hit_count[name]} tid={p.get('tid')} ecx={p.get('ecx')} a0={p.get('a0')}", flush=True)
        for f in (p.get("bt") or [])[:4]:
            bt_count[f] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=120, help="capture window")
    args = ap.parse_args()

    pid = get_pid()
    print(f"[*] PID={pid}, capture={args.seconds}s")
    sess = frida.get_local_device().attach(pid)
    js = JS_TMPL.replace("__CANDS__", json.dumps(CANDIDATES))
    sc = sess.create_script(js)
    sc.on("message", on_message)
    sc.load()

    print("\n" + "=" * 72)
    print("请在窗口内依次执行：A) 发文本  B) 转发已同步语音  C) 若可用触发语音转文字")
    print("=" * 72 + "\n")

    time.sleep(args.seconds)
    try:
        sc.unload()
        sess.detach()
    except Exception:
        pass

    report = {
        "pid": pid,
        "seconds": args.seconds,
        "hits": dict(hit_count),
        "gate_events": gate_count,
        "top_bt": bt_count.most_common(30),
        "events": events,
    }
    out = OUT / f"g7_runtime_probe_{TS}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] report => {out.name}")
    print(f"[+] hit summary: {dict(hit_count)}")


if __name__ == "__main__":
    main()
