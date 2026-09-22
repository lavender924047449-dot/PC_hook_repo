"""G7 · 三合一发送边界探针：mmtls + CGI + CDN 大包，各自独立限流。

桶 A (mmtls_frame): EVP_EncryptUpdate 且 head[4:6] == 07 05 -> 记录 wx+RVA 栈
桶 B (cgi_post):    SSL_write 且开头是 "POST /cgi-bin/" / "POST /hotdog/" -> 解析 URL + wx+RVA
桶 C (bulk_upload): 任何 hook 且 len >= 4096 -> 完整 head + wx+RVA
"""
import argparse, frida, json, subprocess, sys, time
from collections import Counter
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
  try { return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0,16).map(desc); }
  catch(e){ return []; }
}
function hx(p,n){
  try{
    var b = p.readByteArray(n);
    return Array.from(new Uint8Array(b)).map(function(x){return ('0'+x.toString(16)).slice(-2);}).join('');
  } catch(e){ return ''; }
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

var bucketCap = {A: 40, B: 30, C: 40};
var bucketN   = {A: 0,  B: 0,  C: 0};
var totalPerFn = {};

function rec(fn, tid, ctx, buf, len, bucket, extra){
  if (bucketN[bucket] >= bucketCap[bucket]) return;
  bucketN[bucket]++;
  var headLen = Math.min(160, len);
  var payload = {
    t:'hit', bucket: bucket, fn: fn, tid: tid, len: len,
    head: hx(buf, headLen), bt: bt(ctx)
  };
  if (extra) Object.assign(payload, extra);
  send(payload);
}

function tryHook(mod, name, cb){
  var m = Process.findModuleByName(mod);
  if (!m){ send({t:'no_mod', mod:mod}); return; }
  var addr = null;
  try { addr = m.findExportByName(name); } catch(e){}
  if (!addr || addr.isNull()){ send({t:'no_exp', mod:mod, fn:name}); return; }
  var key = mod + '!' + name;
  totalPerFn[key] = 0;
  Interceptor.attach(addr, {
    onEnter: function(args){
      totalPerFn[key]++;
      cb.call(this, args, key);
    }
  });
  send({t:'hooked', fn:key, at:addr.toString()});
}

// ---- EVP_EncryptUpdate(ctx, out, outlen, in, inlen) ----
tryHook('libcrypto-1_1.dll', 'EVP_EncryptUpdate', function(args, key){
  var len; try { len = args[4].toInt32(); } catch(e){ return; }
  if (len < 8 || len > 1<<20) return;
  var buf = args[3];
  // read 6 bytes head, check bytes[4]=0x07 && bytes[5]=0x05
  var b;
  try { b = new Uint8Array(buf.readByteArray(6)); } catch(e){ return; }
  var isMmtls = (b[4] === 0x07 && b[5] === 0x05);
  if (isMmtls) rec(key, this.threadId, this.context, buf, len, 'A', {tag:'mmtls_0705'});
  else if (len >= 4096) rec(key, this.threadId, this.context, buf, len, 'C', {tag:'bulk_evp'});
});

// ---- SSL_write(ssl, buf, len) ----
tryHook('libssl-1_1.dll', 'SSL_write', function(args, key){
  var len; try { len = args[2].toInt32(); } catch(e){ return; }
  if (len < 8 || len > 1<<20) return;
  var buf = args[1];
  var head = readAscii(buf, Math.min(128, len));
  if (head.indexOf('POST /cgi-bin/')===0 || head.indexOf('POST /hotdog/')===0
      || head.indexOf('POST /')===0){
    // parse URL first line
    var eol = head.indexOf('\r');
    var reqline = eol>0 ? head.substring(0, eol) : head.substring(0, 60);
    rec(key, this.threadId, this.context, buf, len, 'B', {tag:'cgi', reqline: reqline});
  } else if (len >= 4096){
    rec(key, this.threadId, this.context, buf, len, 'C', {tag:'bulk_ssl'});
  }
});

// ---- WSASend(sock, bufs, cnt, ...) ----
(function(){
  var m = Process.findModuleByName('ws2_32.dll');
  if (!m) return;
  var addr; try{ addr = m.findExportByName('WSASend'); } catch(e){}
  if (!addr || addr.isNull()) return;
  var key = 'ws2_32.dll!WSASend';
  totalPerFn[key] = 0;
  Interceptor.attach(addr, {
    onEnter: function(args){
      totalPerFn[key]++;
      try{
        var cnt = args[2].toInt32(); if (cnt<=0) return;
        var l = args[1].readU32();
        var p = args[1].add(4).readPointer();
        if (l >= 4096 && l <= 1<<20){
          rec(key, this.threadId, this.context, p, l, 'C', {tag:'bulk_wsasend'});
        }
      } catch(e){}
    }
  });
  send({t:'hooked', fn:key, at:addr.toString()});
})();

// ---- ws2_32!send(sock, buf, len, flags) ----
tryHook('ws2_32.dll', 'send', function(args, key){
  var len; try { len = args[2].toInt32(); } catch(e){ return; }
  if (len < 4096 || len > 1<<20) return;
  rec(key, this.threadId, this.context, args[1], len, 'C', {tag:'bulk_send'});
});

setInterval(function(){
  send({t:'hb', totals: totalPerFn, buckets: bucketN});
}, 5000);
"""


hooked=[]; no_exp=[]; events=[]; totals={}; bstate={}; fatal=None


def get_pid():
    out = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("no pid")


def on_msg(msg, _):
    global fatal
    if msg.get("type") == "error":
        fatal = msg.get("description")
        print(f"[JS ERR] {fatal}\n{msg.get('stack','')}")
        return
    if msg.get("type") != "send": return
    p = msg["payload"]; t = p.get("t")
    if t=='hooked': hooked.append(p); print(f"[hook] {p['fn']} @ {p['at']}")
    elif t=='no_exp': no_exp.append(p); print(f"[NO ] {p['mod']}!{p['fn']}")
    elif t=='no_mod': print(f"[NOMOD] {p['mod']}")
    elif t=='hb':
        totals.clear(); totals.update(p['totals'])
        bstate.clear(); bstate.update(p['buckets'])
        print(f"[hb] buckets A={bstate.get('A',0)} B={bstate.get('B',0)} C={bstate.get('C',0)}  kept={len(events)}")
    elif t=='hit':
        events.append(p)
        extra = p.get('reqline') or p.get('tag') or ''
        print(f"[HIT {p['bucket']}] {p['fn']} len={p['len']} tid={p['tid']} {extra}  head={p['head'][:40]}")


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--seconds", type=int, default=90); a=ap.parse_args()
    pid=get_pid(); print(f"[*] pid={pid} seconds={a.seconds}")
    sess=frida.get_local_device().attach(pid)
    sc=sess.create_script(JS); sc.on("message", on_msg); sc.load()
    print("="*72)
    print("窗口内依次执行 3 步：")
    print("  1) 发一条文本")
    print("  2) 转发一条已同步语音")
    print("  3) 再发一条文本（预留余地）")
    print("="*72)
    time.sleep(a.seconds)
    try: sc.unload()
    except Exception as e: print(f"[!] unload: {e}")
    try: sess.detach()
    except: pass
    report={"pid":pid,"seconds":a.seconds,"hooked":hooked,"no_exp":no_exp,
            "totals_final":totals,"buckets_final":bstate,"events":events,"fatal":fatal}
    out=OUT/f"g7_egress_triple_{TS}.json"
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    print(f"[+] report => {out.name}")
    print(f"[+] events={len(events)}  A={bstate.get('A',0)}  B={bstate.get('B',0)}  C={bstate.get('C',0)}")


if __name__=="__main__": main()
