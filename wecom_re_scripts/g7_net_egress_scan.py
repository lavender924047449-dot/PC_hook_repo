"""G7 · 网络出口全家桶扫描。

目的：找出这版 WXWork 真正的发送边界（可能是 mmtls / 自研 TLS）。

策略：
1. 枚举所有模块，输出名字含 ssl/tls/crypto/mmtls/net 的
2. Hook ws2_32 所有 send 家族
3. 枚举可疑模块的导出函数，凡是名字含 write/send/encrypt/pack 的都 hook
4. 严格限流：每个函数只保留前 4 条 payload>=32 的事件
5. 每条事件带上 wx+ RVA 栈
"""
import argparse
import frida
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")
TS = datetime.now().strftime("%Y%m%d_%H%M%S")

JS = r"""
'use strict';
var wx = Process.getModuleByName('WXWork.exe');

// ---------- 1) enumerate suspicious modules ----------
var mods = Process.enumerateModules();
var interesting = [];
mods.forEach(function(m){
  var n = m.name.toLowerCase();
  if (/ssl|tls|crypto|mmtls|mars|net|http|socket|wechat|wxwork|ww/.test(n)){
    interesting.push({name: m.name, base: m.base.toString(), size: m.size});
  }
});
send({t:'mods', mods: interesting});

// ---------- 2) hook helpers ----------
function u32(p){ try{return p.toUInt32()>>>0;}catch(e){return 0;} }
function desc(p){
  try{
    var v=u32(p);
    for (var i=0;i<mods.length;i++){
      var m=mods[i], b=u32(m.base);
      if (v>=b && v<b+m.size){
        var tag = (m.name === 'WXWork.exe') ? 'wx' : m.name;
        return tag+'+0x'+(v-b).toString(16);
      }
    }
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

var perFnCount = {};
var MAX_PER_FN = 4;
var totalHits = {};

function hookSendLike(modName, fnName, addr, lenArgIdx, bufArgIdx){
  var key = modName + '!' + fnName;
  perFnCount[key] = 0;
  totalHits[key] = 0;
  try {
    Interceptor.attach(addr, {
      onEnter: function(args){
        totalHits[key]++;
        var buf = args[bufArgIdx];
        var lenRaw = args[lenArgIdx];
        var len = 0;
        try { len = lenRaw.toInt32(); } catch(e){ len = 0; }
        if (len < 32 || len > 1<<20) return;
        if (perFnCount[key] >= MAX_PER_FN) return;
        perFnCount[key]++;
        send({
          t:'send',
          fn: key,
          tid: this.threadId,
          len: len,
          head: hx(buf, Math.min(96, len)),
          bt: bt(this.context)
        });
      }
    });
    send({t:'hooked', fn: key, at: addr.toString()});
  } catch(e){
    send({t:'hook_err', fn: key, err: e.toString()});
  }
}

// ws2_32 family
var ws2 = Module.findBaseAddress('ws2_32.dll');
if (ws2){
  var send_a = Module.findExportByName('ws2_32.dll', 'send');
  var sendto = Module.findExportByName('ws2_32.dll', 'sendto');
  var wsasend = Module.findExportByName('ws2_32.dll', 'WSASend');
  var wsasendto = Module.findExportByName('ws2_32.dll', 'WSASendTo');
  if (send_a)   hookSendLike('ws2_32', 'send',       send_a,   2, 1);
  if (sendto)   hookSendLike('ws2_32', 'sendto',     sendto,   2, 1);
  if (wsasend){
    // WSASend(sock, LPWSABUF, dwBufferCount, ...) — WSABUF={len, buf}
    var key = 'ws2_32!WSASend';
    perFnCount[key]=0; totalHits[key]=0;
    Interceptor.attach(wsasend, {
      onEnter: function(args){
        totalHits[key]++;
        var bufsPtr = args[1];
        var cnt = args[2].toInt32();
        if (cnt<=0) return;
        var b0 = bufsPtr;
        var l = b0.readU32();
        var p = b0.add(4).readPointer();
        if (l < 32 || l > 1<<20) return;
        if (perFnCount[key] >= MAX_PER_FN) return;
        perFnCount[key]++;
        send({t:'send', fn:key, tid:this.threadId, len:l, head:hx(p, Math.min(96,l)), bt:bt(this.context)});
      }
    });
    send({t:'hooked', fn:key, at:wsasend.toString()});
  }
}

// enum interesting module exports and hook write/send/encrypt/pack
interesting.forEach(function(m){
  if (m.name.toLowerCase() === 'ws2_32.dll') return;
  if (m.name === 'WXWork.exe') return;
  var exps = [];
  try { exps = Module.enumerateExports(m.name); } catch(e){ return; }
  exps.forEach(function(e){
    if (e.type !== 'function') return;
    var lname = e.name.toLowerCase();
    if (/^(ssl_write|write|send|encrypt|pack|mmtls_?send|mmtls_?write)$/.test(lname)
        || (/^ssl_/.test(lname) && /write|send/.test(lname))){
      // assume (ctx, buf, len) — try lenArg=2, bufArg=1
      hookSendLike(m.name, e.name, e.address, 2, 1);
    }
  });
});

setInterval(function(){
  send({t:'hb', totals: totalHits});
}, 5000);
"""


mods = []
hooked = []
hook_err = []
events = []
totals = {}


def get_pid():
    out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("no wxwork pid on :9882")


def on_msg(msg, _):
    if msg.get("type") != "send":
        return
    p = msg["payload"]
    t = p.get("t")
    if t == "mods":
        mods.extend(p["mods"])
        print(f"[+] interesting modules: {len(mods)}")
        for m in mods:
            print(f"    {m['name']:<40} base={m['base']} size={m['size']}")
    elif t == "hooked":
        hooked.append(p)
        print(f"[hook] {p['fn']} @ {p['at']}")
    elif t == "hook_err":
        hook_err.append(p)
    elif t == "hb":
        totals.clear()
        totals.update(p["totals"])
        active = {k: v for k, v in totals.items() if v > 0}
        print(f"[hb] active hooks: {len(active)}  events_kept={len(events)}")
        for k, v in sorted(active.items(), key=lambda x: -x[1])[:8]:
            print(f"    {v:>5}  {k}")
    elif t == "send":
        events.append(p)
        print(f"[SEND] {p['fn']} tid={p['tid']} len={p['len']} head={p['head'][:32]}...")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=60)
    args = ap.parse_args()
    pid = get_pid()
    print(f"[*] pid={pid} seconds={args.seconds}")
    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(JS)
    sc.on("message", on_msg)
    sc.load()
    print("=" * 72)
    print("窗口内执行：1) 发文本 1 条   2) 转发已同步语音 1 条")
    print("=" * 72)
    time.sleep(args.seconds)
    try: sc.unload()
    except Exception as e: print(f"[!] unload: {e}")
    try: sess.detach()
    except Exception as e: print(f"[!] detach: {e}")
    report = {
        "pid": pid,
        "seconds": args.seconds,
        "interesting_modules": mods,
        "hooked": hooked,
        "hook_errors": hook_err,
        "totals_final": totals,
        "events": events,
    }
    out = OUT / f"g7_net_egress_{TS}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] report => {out.name}")
    print(f"[+] hooked={len(hooked)}  kept_events={len(events)}")


if __name__ == "__main__":
    main()
