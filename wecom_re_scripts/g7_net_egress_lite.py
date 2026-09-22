"""G7 · 精简网络出口探针（无 enumerateExports，避免大模块卡死）。

固定 hook：
- ws2_32: send, sendto, WSASend, WSASendTo
- libssl-1_1: SSL_write, SSL_write_ex
- libcrypto-1_1: EVP_EncryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptFinal
- libcurl.ssl1.1: curl_easy_send, Curl_write, Curl_sendf
"""
import argparse, frida, json, subprocess, sys, time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
TS = datetime.now().strftime("%Y%m%d_%H%M%S")

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');
var wxBase = wx.base, wxSize = wx.size;

function u32(p){ try{return p.toUInt32()>>>0;}catch(e){return 0;} }
function desc(p){
  try{
    var v=u32(p), b=u32(wxBase);
    if (v>=b && v<b+wxSize) return 'wx+0x'+(v-b).toString(16);
    return '0x'+v.toString(16);
  } catch(e){ return '?'; }
}
function bt(ctx){
  try { return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0,14).map(desc); }
  catch(e){ return []; }
}
function hx(p,n){
  try{
    var b = p.readByteArray(n);
    return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join('');
  } catch(e){ return ''; }
}

var perFn = {};
var MAX_PER = 6;
var total = {};

function tryHook(mod, name, lenArgIdx, bufArgIdx){
  var m = Process.findModuleByName(mod);
  if (!m){ send({t:'no_mod', mod:mod}); return; }
  var addr = null;
  try { addr = m.findExportByName(name); } catch(e){}
  if (!addr || addr.isNull()){ send({t:'no_exp', mod:mod, fn:name}); return; }
  var key = mod + '!' + name;
  perFn[key]=0; total[key]=0;
  Interceptor.attach(addr, {
    onEnter: function(args){
      total[key]++;
      var len = 0;
      try { len = args[lenArgIdx].toInt32(); } catch(e){}
      if (len<32 || len>1<<20) return;
      if (perFn[key]>=MAX_PER) return;
      perFn[key]++;
      send({t:'hit', fn:key, tid:this.threadId, len:len, head:hx(args[bufArgIdx], Math.min(96,len)), bt:bt(this.context)});
    }
  });
  send({t:'hooked', fn:key, at:addr.toString()});
}

function tryHookWSASend(){
  var m = Process.findModuleByName('ws2_32.dll');
  if (!m){ send({t:'no_mod', mod:'ws2_32.dll'}); return; }
  var addr = null;
  try { addr = m.findExportByName('WSASend'); } catch(e){}
  if (!addr || addr.isNull()){ send({t:'no_exp', mod:'ws2_32.dll', fn:'WSASend'}); return; }
  var key = 'ws2_32.dll!WSASend';
  perFn[key]=0; total[key]=0;
  Interceptor.attach(addr, {
    onEnter: function(args){
      total[key]++;
      try{
        var bufsPtr = args[1], cnt = args[2].toInt32();
        if (cnt<=0) return;
        var l = bufsPtr.readU32();
        var p = bufsPtr.add(4).readPointer();
        if (l<32 || l>1<<20) return;
        if (perFn[key]>=MAX_PER) return;
        perFn[key]++;
        send({t:'hit', fn:key, tid:this.threadId, len:l, head:hx(p, Math.min(96,l)), bt:bt(this.context)});
      } catch(e){}
    }
  });
  send({t:'hooked', fn:key, at:addr.toString()});
}

tryHook('ws2_32.dll', 'send', 2, 1);
tryHook('ws2_32.dll', 'sendto', 2, 1);
tryHookWSASend();

tryHook('libssl-1_1.dll', 'SSL_write', 2, 1);
tryHook('libssl-1_1.dll', 'SSL_write_ex', 2, 1);

tryHook('libcrypto-1_1.dll', 'EVP_EncryptUpdate', 4, 3); // (ctx, out, outlen, in, inlen)
// note: len is args[4] (5th), in-buf is args[3]

tryHook('libcurl.ssl1.1.dll', 'curl_easy_send', 2, 1);

setInterval(function(){ send({t:'hb', total: total}); }, 5000);
"""


hooked=[]; no_exp=[]; events=[]; totals={}


def get_pid():
    out = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("no wxwork pid on :9882")


def on_msg(msg, _):
    if msg.get("type") == "error":
        print(f"[JS ERROR] {msg.get('description')}\n{msg.get('stack','')}")
        return
    if msg.get("type") != "send": return
    p = msg["payload"]
    t = p.get("t")
    if t=='hooked':
        hooked.append(p); print(f"[hook] {p['fn']} @ {p['at']}")
    elif t=='no_exp':
        no_exp.append(p); print(f"[NO ] {p['mod']}!{p['fn']}")
    elif t=='no_mod':
        print(f"[NOMOD] {p['mod']}")
    elif t=='hb':
        totals.clear(); totals.update(p['total'])
        active={k:v for k,v in totals.items() if v>0}
        print(f"[hb] active={len(active)} kept={len(events)}  " + ", ".join(f"{k.split('!')[-1]}={v}" for k,v in sorted(active.items(), key=lambda x:-x[1])[:6]))
    elif t=='hit':
        events.append(p)
        print(f"[HIT] {p['fn']} tid={p['tid']} len={p['len']} head={p['head'][:32]}")


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--seconds", type=int, default=60)
    a=ap.parse_args()
    pid=get_pid(); print(f"[*] pid={pid} seconds={a.seconds}")
    sess=frida.get_local_device().attach(pid)
    sc=sess.create_script(JS); sc.on("message", on_msg); sc.load()
    print("="*72); print("窗口内：1) 发文本  2) 转发已同步语音"); print("="*72)
    time.sleep(a.seconds)
    try: sc.unload()
    except Exception as e: print(f"[!] unload: {e}")
    try: sess.detach()
    except: pass
    report={"pid":pid,"seconds":a.seconds,"hooked":hooked,"no_exp":no_exp,
            "totals_final":totals,"events":events}
    out=OUT/f"g7_egress_lite_{TS}.json"
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    print(f"[+] report => {out.name}")
    print(f"[+] hooked={len(hooked)}  events_kept={len(events)}")
    for k,v in sorted(totals.items(), key=lambda x:-x[1]):
        print(f"    total {v:>6}  {k}")


if __name__=="__main__": main()
