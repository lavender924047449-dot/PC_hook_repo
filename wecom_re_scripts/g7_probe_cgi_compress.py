"""G7 · Hook §46 的 CGI `before compress` 点，只保留 CGI#1001 (send message)。

被 hook 的绝对地址：wxBase + 0x963E58A（§46 已证稳定触发）。
优化：脚本内做限流 + 只对含 '1001' 的 arg2 头做 send()，避免压垮 Frida 消息队列。
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
var CGI = wx.base.add(0x963E58A);

send({t:'ready', cgi: CGI.toString(), wxbase: wx.base.toString()});

function u32(p){ try{return p.toUInt32()>>>0;}catch(e){return 0;} }
function desc(p){
  try{
    var v=u32(p), b=u32(wx.base);
    if (v>=b && v<b+wx.size) return 'wx+0x'+(v-b).toString(16);
    return '0x'+v.toString(16);
  } catch(e){ return '?'; }
}
function bt(ctx){
  try { return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0,16).map(desc); }
  catch(e){ return []; }
}
function hx(p,n){
  try{
    var b = p.readByteArray(n);
    return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join('');
  } catch(e){ return ''; }
}
function readCString(p, max){
  try { return p.readCString(max); } catch(e){ return ''; }
}
function readAscii(p, n){
  try{
    var b = new Uint8Array(p.readByteArray(n));
    var s='';
    for (var i=0;i<b.length;i++){
      var c=b[i]; s += (c>=32 && c<127) ? String.fromCharCode(c) : '.';
    }
    return s;
  } catch(e){ return ''; }
}

var total = 0;
var kept = 0;
var MAX_KEEP = 60;

Interceptor.attach(CGI, {
  onEnter: function(args){
    total++;
    if (kept >= MAX_KEEP) return;
    var a2 = args[2];
    if (a2.isNull()) return;
    // scan first 512 bytes for "1001" ascii — cheap prefilter
    var head = readAscii(a2, 512);
    if (head.indexOf('1001') < 0) return;
    kept++;
    send({
      t:'cgi',
      tid: this.threadId,
      idx: kept,
      total_so_far: total,
      a2: a2.toString(),
      head_hex: hx(a2, 96),
      head_ascii: head,
      bt: bt(this.context)
    });
  }
});

// heartbeat every 5s
setInterval(function(){
  send({t:'hb', total: total, kept: kept});
}, 5000);
"""


events = []
wx_frames = Counter()
totals = {"total": 0, "kept": 0}


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
        print(f"[+] CGI hook @ {p.get('cgi')}  wxbase={p.get('wxbase')}")
    elif t == "hb":
        totals["total"] = p.get("total")
        totals["kept"] = p.get("kept")
        print(f"[hb] total={totals['total']} kept={totals['kept']} recv_events={len(events)}")
    elif t == "cgi":
        events.append(p)
        head = p.get("head_ascii", "")[:80]
        print(f"[CGI#{p.get('idx')}] tid={p.get('tid')} a2={p.get('a2')} head={head!r}")
        for f in p.get("bt", [])[:12]:
            if f.startswith("wx+0x"):
                wx_frames[f] += 1


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

    try:
        sc.unload()
    except Exception as e:
        print(f"[!] unload: {e}")
    try:
        sess.detach()
    except Exception as e:
        print(f"[!] detach: {e}")

    report = {
        "pid": pid,
        "seconds": args.seconds,
        "totals": totals,
        "events": events,
        "top_wx_frames": wx_frames.most_common(80),
    }
    out = OUT / f"g7_cgi_compress_{TS}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] report => {out.name}")
    print(f"[+] total_cgi_hits={totals.get('total')} kept_1001={len(events)}")
    if wx_frames:
        print("  top wx frames (CGI#1001 backtrace):")
        for f, c in wx_frames.most_common(15):
            print(f"    {c:>3}  {f}")


if __name__ == "__main__":
    main()
