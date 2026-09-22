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
var ws2 = Process.getModuleByName('ws2_32.dll');
var PRESEND = wx.base.add(0x919ffb2);
var WSASEND = ws2.findExportByName('WSASend');

if (!WSASEND) {
  send({t:'err', msg:'WSASend not found'});
} else {
  send({t:'ready', wsasend:WSASEND.toString(), wxbase:wx.base.toString()});
}

var gate = {};
function u32(p){ try{return p.toUInt32()>>>0;}catch(e){return 0;} }
function desc(p){
  try{
    var v=u32(p), b=u32(wx.base);
    if (v>=b && v<b+wx.size) return 'wx+0x'+(v-b).toString(16);
    return '0x'+v.toString(16);
  } catch(e){ return '?'; }
}
function bt(ctx){
  try { return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0,12).map(desc); }
  catch(e){ return []; }
}

Interceptor.attach(PRESEND, {
  onEnter: function(){ gate[this.threadId]=(gate[this.threadId]||0)+1; },
  onLeave: function(){
    var n=(gate[this.threadId]||1)-1;
    if (n<=0) delete gate[this.threadId]; else gate[this.threadId]=n;
  }
});

var seq = 0;
Interceptor.attach(WSASEND, {
  onEnter: function(args){
    // int WSASend(SOCKET s, LPWSABUF bufs, DWORD bufCount, ...)
    var tid = this.threadId;
    var inGate = !!gate[tid];
    var bufs = args[1];
    var cnt = args[2].toInt32();
    var total = 0;
    var b0 = '';
    try {
      if (cnt > 0 && cnt < 32) {
        for (var i=0;i<cnt;i++){
          var p = bufs.add(i*8).readPointer();
          var n = bufs.add(i*8+4).readU32();
          total += n;
          if (!b0 && n > 0 && n < 0x100000) {
            var raw = p.readByteArray(Math.min(n, 32));
            b0 = Array.from(new Uint8Array(raw)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join('');
          }
        }
      }
    } catch(e){}

    var stack = bt(this.context);
    // keep all in presend; out-of-presend only small sampling (every 80th) to reduce noise
    if (!inGate && (++seq % 80 !== 0)) return;
    send({
      t:'send',
      in_presend: inGate,
      tid: tid,
      cnt: cnt,
      total: total,
      b0: b0,
      bt: stack
    });
  }
});
"""


events = []
wx_frames = Counter()
pre_frames = Counter()


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
    if t == "ready":
        print(f"[+] WSASend={p.get('wsasend')} wxbase={p.get('wxbase')}")
    elif t == "err":
        print("[ERR]", p.get("msg"))
    elif t == "send":
        events.append(p)
        tag = "IN" if p.get("in_presend") else "OUT"
        print(f"[SEND:{tag}] tid={p.get('tid')} total={p.get('total')} cnt={p.get('cnt')} b0={p.get('b0')[:16]}")
        for f in p.get("bt", [])[:8]:
            if f.startswith("wx+0x"):
                wx_frames[f] += 1
                if p.get("in_presend"):
                    pre_frames[f] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=120)
    args = ap.parse_args()
    pid = get_pid()
    print(f"[*] pid={pid} seconds={args.seconds}")

    sess = frida.get_local_device().attach(pid)
    sc = sess.create_script(JS)
    sc.on("message", on_msg)
    sc.load()

    print("=" * 72)
    print("窗口内执行：发文本 + 转发已同步语音（至少各一次）")
    print("=" * 72)
    time.sleep(args.seconds)

    try:
        sc.unload()
        sess.detach()
    except Exception:
        pass

    report = {
        "pid": pid,
        "seconds": args.seconds,
        "events": events,
        "top_wx_frames": wx_frames.most_common(80),
        "top_presend_wx_frames": pre_frames.most_common(80),
    }
    out = OUT / f"g7_wsasend_bt_{TS}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] report => {out.name}")
    print(f"[+] total events={len(events)} presend wx frames={len(pre_frames)}")


if __name__ == "__main__":
    main()
