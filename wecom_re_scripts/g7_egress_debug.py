"""调试用：一次只装一个 hook，找出 tryHook 里到底哪行 not-a-function。"""
import frida, subprocess, sys, time

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

JS = r"""
'use strict';
send({t:'log', m:'boot'});

try {
  send({t:'log', m:'M1 findBase ws2_32=' + Module.findBaseAddress('ws2_32.dll')});
} catch(e){ send({t:'log', m:'M1 err '+e}); }

var addr;
try {
  addr = Module.findExportByName('ws2_32.dll', 'send');
  send({t:'log', m:'M2 findExport send=' + addr + ' typeof=' + (typeof addr)});
} catch(e){ send({t:'log', m:'M2 err '+e}); }

try {
  send({t:'log', m:'M3 addr is null: ' + (addr === null) + ' isNull: ' + (addr && addr.isNull && addr.isNull())});
} catch(e){ send({t:'log', m:'M3 err '+e}); }

try {
  Interceptor.attach(addr, {
    onEnter: function(args){ send({t:'log', m:'hit send'}); }
  });
  send({t:'log', m:'M4 attach ok'});
} catch(e){ send({t:'log', m:'M4 err '+e+' stack='+(e.stack||'')}); }

setTimeout(function(){ send({t:'log', m:'timer fired'}); }, 3000);
"""


def get_pid():
    out = subprocess.run(["netstat","-ano"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if ":9882" in line and "LISTENING" in line:
            return int(line.strip().split()[-1])
    raise RuntimeError("no pid")


def on_msg(msg, _):
    if msg.get("type") == "error":
        print(f"[JS ERR] {msg.get('description')}")
        return
    if msg.get("type") == "send":
        print(f"[js] {msg['payload'].get('m')}")


pid = get_pid()
print(f"pid={pid}")
sess = frida.get_local_device().attach(pid)
sc = sess.create_script(JS)
sc.on("message", on_msg)
sc.load()
time.sleep(6)
try: sc.unload()
except: pass
try: sess.detach()
except: pass
