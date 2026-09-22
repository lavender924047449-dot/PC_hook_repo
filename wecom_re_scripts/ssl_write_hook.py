"""
hook libssl-1_1.dll 的 SSL_write，捕获 WXWork 所有出站 HTTPS 明文。

SSL_write(SSL *ssl, const void *buf, int num)
  → 我们在加密前读 buf[0..num-1]

用法：
  python ssl_write_hook.py [--save] [--filter KEYWORD]
  --save     : 把所有请求 dump 到 ssl_write_capture_HHMMSS.json
  --filter   : 只打印包含指定关键字的请求（不区分大小写）
"""
import sys, time, json, argparse, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent

JS = r"""
'use strict';
const libssl = Process.getModuleByName('libssl-1_1.dll');
const FILTER = __FILTER__;   // null or string

const ssl_write = libssl.findExportByName('SSL_write');
if (!ssl_write){ send({t:'err', msg:'SSL_write not found'}); }
else {
    send({t:'ready', fn: ssl_write.toString()});
}

let seq = 0;
let totalBytes = 0;

Interceptor.attach(ssl_write, {
    onEnter: function(args){
        try {
            const buf = args[1];
            const num = args[2].toInt32();
            if (num <= 0 || num > 1024*1024) return;   // 忽略异常大小
            totalBytes += num;

            let data = '';
            try {
                const raw = new Uint8Array(buf.readByteArray(Math.min(num, 4096)));
                // 尝试 UTF-8 文本
                let isText = true;
                for (let i=0;i<Math.min(raw.length,64);i++){
                    if (raw[i]<9 || (raw[i]>13 && raw[i]<32 && raw[i]!==0x1b)){ isText=false; break; }
                }
                if (isText){
                    data = String.fromCharCode.apply(null, raw);
                } else {
                    // hex dump (前 256B)
                    data = '[binary] ' + Array.from(raw.slice(0,256))
                               .map(b=>b.toString(16).padStart(2,'0')).join(' ');
                }
            } catch(e){ data = '[read error]'; }

            const id = ++seq;

            // 过滤
            if (FILTER && data.toLowerCase().indexOf(FILTER) < 0) return;

            send({t:'write', id, num,
                  data_head: data.slice(0, 2000),
                  is_full: data.length <= 2000});
        } catch(e){ /* ignore */ }
    }
});

// 也 hook SSL_read 用于确认通信方向
const ssl_read = libssl.findExportByName('SSL_read');
if (ssl_read){
    Interceptor.attach(ssl_read, {
        onLeave: function(retval){
            try {
                const n = retval.toInt32();
                if (n <= 0 || n > 1024*1024) return;
                // only count, don't log unless needed
            } catch(e){}
        }
    });
}
""".replace("__FILTER__", "null")

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--save",   action="store_true")
    ap.add_argument("--filter", default="", help="only show writes containing this string")
    ap.add_argument("--duration", type=int, default=120)
    args = ap.parse_args()

    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    js = JS.replace("null", f'"{args.filter.lower()}"') if args.filter else JS

    import frida
    sess   = frida.get_local_device().attach(pid)
    scr    = sess.create_script(js)
    events = []

    def on_msg(m, _):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "ready":
                print(f"[+] PID={pid}  SSL_write hooked @ {p['fn']}")
                print(f"[*] filter={'(none)' if not args.filter else args.filter!r}")
                print("="*65)
            elif p.get("t") == "write":
                events.append(p)
                head = p["data_head"]
                trunc = "" if p["is_full"] else f"  [+{p['num']-2000}B truncated]"
                print(f"\n[#{p['id']:>4}] SSL_write {p['num']}B{trunc}")
                # 截断长请求打印前 800 字符
                print(head[:800])
                if len(head) > 800: print(f"  ... [{len(head)-800} more chars]")
            elif p.get("t") == "err":
                print("[ERR]", p.get("msg"))
        elif m.get("type") == "error":
            print("[FRIDA ERR]", m.get("description"))

    scr.on("message", on_msg)
    scr.load()
    time.sleep(0.5)

    print(f"[*] 监听 {args.duration}s  ── 现在在企微里发消息 ──")
    t0 = time.time()
    while time.time() - t0 < args.duration:
        time.sleep(0.5)

    try: scr.unload(); sess.detach()
    except: pass

    print(f"\n[+] 共捕获 {len(events)} 次 SSL_write")
    if args.save and events:
        out = OUT_DIR / f"ssl_write_capture_{time.strftime('%H%M%S')}.json"
        out.write_text(json.dumps(events, ensure_ascii=False, indent=2))
        print(f"[+] → {out.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
