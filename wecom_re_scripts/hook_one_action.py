"""
单次操作 hook：只捕获本次运行里首次出现的 NEW caller（排除已知 caller）。
指定 --known-callers 跳过已见的 RVA，只报告新出现的。
超时 60s 自动退出。
"""
import sys, time, json, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent
CTOR_RVAS = [0x2b738a2, 0x2b74832]
KNOWN = {"0x919c941", "0x2b7abfd"}   # text message callers 已知

JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
const W0 = wx.base.toUInt32();
const KNOWN = new Set(__KNOWN__);
send({t:'ready'});

const seen = {};
for (const rva of __CTORS__){
    const va = (W0 + rva) >>> 0;
    Interceptor.attach(ptr(va), {
        onEnter: function(){
            try {
                const retVA = this.returnAddress.toUInt32();
                const callerRva = '0x' + ((retVA - W0) >>> 0).toString(16);
                if (seen[callerRva] || KNOWN.has(callerRva)) return;
                seen[callerRva] = true;
                // ctx before (32B) + after (128B)
                let before = '', after = '';
                try { const b = new Uint8Array(this.returnAddress.sub(32).readByteArray(32));
                      before = Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(' '); } catch(e){}
                try { const a = new Uint8Array(this.returnAddress.readByteArray(128));
                      after  = Array.from(a).map(x=>x.toString(16).padStart(2,'0')).join(' '); } catch(e){}
                send({t:'new_caller', caller_rva: callerRva,
                      ctor_rva: '0x'+rva.toString(16),
                      before, after});
            } catch(e){ send({t:'err', msg:e.message}); }
        }
    });
}
""".replace("__CTORS__", json.dumps(CTOR_RVAS)) \
   .replace("__KNOWN__", json.dumps(sorted(KNOWN)))

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def decode_snippet(h):
    import struct
    b = bytes.fromhex(h.replace(' ',''))
    lines, i = [], 0
    while i < len(b) and len(lines) < 40:
        op = b[i]
        if op == 0xC6 and i+3 < len(b) and (b[i+1]&0xC0) == 0x40:
            off = b[i+2]; imm = b[i+3]
            rm  = b[i+1]&7
            rn  = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][rm]
            flag = " ←←← SUBTYPE WRITE!" if off==0x50 else ""
            lines.append(f"  +{i:03x}: MOV byte [{rn}+0x{off:02x}], 0x{imm:02x}{flag}"); i+=4
        elif op == 0xC7 and i+6 < len(b) and (b[i+1]&0xC0) == 0x40:
            off = b[i+2]; imm = struct.unpack_from("<I",b,i+3)[0]
            rm  = b[i+1]&7
            rn  = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][rm]
            flag = " ←←← SUBTYPE WRITE!" if off==0x50 else ""
            lines.append(f"  +{i:03x}: MOV dword [{rn}+0x{off:02x}], 0x{imm:08x}{flag}"); i+=7
        elif op == 0x6A:
            lines.append(f"  +{i:03x}: PUSH byte 0x{b[i+1]:02x}"); i+=2
        elif op == 0xE8 and i+4 < len(b):
            rel = struct.unpack_from("<i",b,i+1)[0]
            lines.append(f"  +{i:03x}: CALL (rel +0x{rel:08x})"); i+=5
        elif op == 0xEB:
            lines.append(f"  +{i:03x}: JMP short {struct.unpack_from('b',b,i+1)[0]+2:+d}"); i+=2
        else:
            lines.append(f"  +{i:03x}: {op:02x}..."); i+=1
    return lines

def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "file"
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script  = session.create_script(JS)
    ready = {"v": False}
    found = []

    def on_msg(m,_):
        if m.get("type")=="send":
            p = m["payload"]
            if p.get("t")=="ready": ready["v"]=True
            elif p.get("t")=="new_caller":
                found.append(p)
                print(f"\n[!!! NEW caller for '{action}'] rva={p['caller_rva']}  ctor={p['ctor_rva']}")
                print("  -- before CALL (last 32B) --")
                for ln in decode_snippet(p["before"]): print(ln)
                print("  -- after  CALL (next 128B) --")
                for ln in decode_snippet(p["after"]):  print(ln)
            elif p.get("t")=="err":
                print("[ERR]", p.get("msg"))
        elif m.get("type")=="error":
            print("[ERR]", m.get("description"))

    script.on("message", on_msg)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    print(f"[*] Hook 就绪 PID={pid}. 60 秒窗口.")
    print(f"[*] 请立刻执行: {action}")
    t0 = time.time()
    while time.time()-t0 < 60:
        time.sleep(0.5)
        if found: break   # 找到就提前退出

    if not found:
        print("[=] 60s 内未检测到新 caller（该操作可能使用已知 caller 或未触发 ctor）")
    else:
        print(f"\n[+] 找到 {len(found)} 个新 caller")

    out = OUT_DIR / f"hook_one_{action}_{time.strftime('%H%M%S')}.json"
    out.write_text(json.dumps({"action":action,"pid":pid,"found":found},
                              ensure_ascii=False, indent=2))
    print(f"[+] → {out.name}")
    try: script.unload(); session.detach()
    except: pass
    return 0

if __name__ == "__main__":
    sys.exit(main())
