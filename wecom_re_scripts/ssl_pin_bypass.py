"""
WXWork OpenSSL 1.1 证书验证 bypass。
hook libssl-1_1.dll 的 SSL_CTX_set_verify，
强制 verify_mode = SSL_VERIFY_NONE (0)，使 mitmproxy 证书被接受。
"""
import sys, time, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

JS = r"""
'use strict';

// libssl-1_1.dll 在 WXWork 自己目录下
const libssl = Process.getModuleByName('libssl-1_1.dll');
const libcrypto = Process.getModuleByName('libcrypto-1_1.dll');
send({t:'ready',
      ssl_base: libssl.base.toString(),
      crypto_base: libcrypto.base.toString()});

// 1) hook SSL_CTX_set_verify → 强制 mode=0 (VERIFY_NONE)
const set_verify = libssl.findExportByName('SSL_CTX_set_verify');
if (set_verify){
    Interceptor.attach(set_verify, {
        onEnter: function(args){
            const old_mode = args[1].toInt32();
            args[1] = ptr(0);     // SSL_VERIFY_NONE = 0
            send({t:'hook', fn:'SSL_CTX_set_verify',
                  old_mode: old_mode, new_mode: 0});
        }
    });
    send({t:'hook_ok', fn:'SSL_CTX_set_verify'});
} else {
    send({t:'hook_miss', fn:'SSL_CTX_set_verify'});
}

// 2) hook SSL_CTX_set_cert_verify_callback → 置为 null（禁用自定义验证回调）
const set_cvb = libssl.findExportByName('SSL_CTX_set_cert_verify_callback');
if (set_cvb){
    Interceptor.attach(set_cvb, {
        onEnter: function(args){
            args[1] = ptr(0);   // callback = NULL
            args[2] = ptr(0);   // arg = NULL
            send({t:'hook', fn:'SSL_CTX_set_cert_verify_callback', zeroed:true});
        }
    });
    send({t:'hook_ok', fn:'SSL_CTX_set_cert_verify_callback'});
}

// 3) hook X509_verify_cert → 永远返回 1 (success)
const verify_cert = libcrypto.findExportByName('X509_verify_cert');
if (verify_cert){
    Interceptor.replace(verify_cert,
        new NativeCallback(function(ctx){ return 1; }, 'int', ['pointer']));
    send({t:'hook_ok', fn:'X509_verify_cert → always 1'});
} else {
    send({t:'hook_miss', fn:'X509_verify_cert'});
}

send({t:'done', msg:'SSL pin bypass active — start mitmproxy and set system proxy to 127.0.0.1:8080'});
"""

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    import frida
    sess = frida.get_local_device().attach(pid)
    scr  = sess.create_script(JS)

    def on_msg(m,_):
        if m.get("type")=="send":
            p = m["payload"]
            t = p.get("t","")
            if t=="ready":
                print(f"[+] libssl  @ {p['ssl_base']}")
                print(f"[+] libcrypto @ {p['crypto_base']}")
            elif t=="hook_ok":
                print(f"  ✓ hooked  {p['fn']}")
            elif t=="hook_miss":
                print(f"  ✗ NOT FOUND: {p['fn']}")
            elif t=="hook":
                print(f"  [intercept] {p['fn']}  {p}")
            elif t=="done":
                print(f"\n[*] {p['msg']}")
        elif m.get("type")=="error":
            print("[ERR]", m.get("description"))

    scr.on("message", on_msg)
    scr.load()

    print(f"[+] SSL pin bypass attached PID={pid}")
    print("    保持运行... Ctrl-C 退出")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass
    try: scr.unload(); sess.detach()
    except: pass
    return 0

if __name__=="__main__":
    sys.exit(main())
