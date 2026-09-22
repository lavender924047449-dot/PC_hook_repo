"""
从进程内存 dump caller RVA 0x919c941 附近 ±512B，
搜索所有 MOV [reg+0x50], imm 写入（即 subtype 写入点）。
"""
import sys, time, json, subprocess, struct
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent

CALLER_RVA = 0x919c941   # call 指令 return address
WINDOW_BEFORE = 256      # 往前读多少字节（找函数起始）
WINDOW_AFTER  = 512      # 往后读多少字节（找 subtype 写入）

JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
const W0 = wx.base.toUInt32();
const callRetVA = (W0 + __CALLER_RVA__) >>> 0;

rpc.exports = {
    dump: function(){
        const startVA = (callRetVA - __BEFORE__) >>> 0;
        const totalLen = __BEFORE__ + __AFTER__;
        let hex = '';
        try {
            const raw = new Uint8Array(ptr(startVA).readByteArray(totalLen));
            hex = Array.from(raw).map(b=>b.toString(16).padStart(2,'0')).join(' ');
        } catch(e){ return {err: e.message}; }
        return {
            start_va: '0x' + startVA.toString(16),
            call_ret_va: '0x' + callRetVA.toString(16),
            call_offset: __BEFORE__,
            hex
        };
    }
};
send({t:'ready'});
""".replace("__CALLER_RVA__", hex(CALLER_RVA)) \
   .replace("__BEFORE__", str(WINDOW_BEFORE)) \
   .replace("__AFTER__",  str(WINDOW_AFTER))

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def decode(data: bytes, base_offset: int, call_offset: int):
    """打印 +0x50 相关的写入，以及 CALL/JMP/RET 关键骨架"""
    lines, i = [], 0
    while i < len(data):
        off = base_offset + i
        b = data[i]
        rel_to_call = i - call_offset

        # MOV byte [reg+disp8], imm8   c6 /2 disp8 imm8
        if b == 0xC6 and i+3 < len(data) and (data[i+1] & 0xC0) == 0x40:
            rm  = data[i+1] & 7
            d8  = data[i+2]; imm = data[i+3]
            rn  = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][rm]
            tag = " ◄◄◄ SUBTYPE!" if d8 == 0x50 else ""
            lines.append((off, rel_to_call,
                f"MOV byte [{rn}+0x{d8:02x}], 0x{imm:02x} ({imm}){tag}")); i += 4
        # MOV dword [reg+disp8], imm32  c7 /0 disp8 imm32
        elif b == 0xC7 and i+6 < len(data) and (data[i+1] & 0xC0) == 0x40:
            rm  = data[i+1] & 7
            d8  = data[i+2]; imm = struct.unpack_from("<I", data, i+3)[0]
            rn  = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][rm]
            tag = " ◄◄◄ SUBTYPE!" if d8 == 0x50 else ""
            lines.append((off, rel_to_call,
                f"MOV dword [{rn}+0x{d8:02x}], 0x{imm:08x} ({imm}){tag}")); i += 7
        # MOV byte [reg+disp32], imm8   c6 /2 disp32 imm8
        elif b == 0xC6 and i+6 < len(data) and (data[i+1] & 0xC0) == 0x80:
            rm  = data[i+1] & 7
            d32 = struct.unpack_from("<I", data, i+2)[0]
            imm = data[i+6]
            rn  = ['eax','ecx','edx','ebx','esp','ebp','esi','edi'][rm]
            tag = " ◄◄◄ SUBTYPE!" if d32 == 0x50 else ""
            lines.append((off, rel_to_call,
                f"MOV byte [{rn}+0x{d32:08x}], 0x{imm:02x} ({imm}){tag}")); i += 7
        # CALL rel32
        elif b == 0xE8 and i+4 < len(data):
            rel = struct.unpack_from("<i", data, i+1)[0]
            arrow = " ←← this is the CTOR call" if rel_to_call == -5 else ""
            lines.append((off, rel_to_call,
                f"CALL rel32 (target +0x{rel:08x}){arrow}")); i += 5
        # RET
        elif b in (0xC2, 0xC3):
            lines.append((off, rel_to_call, "RET")); i += (3 if b==0xC2 else 1)
        # PUSH imm8/imm32
        elif b == 0x6A:
            lines.append((off, rel_to_call, f"PUSH 0x{data[i+1]:02x}")); i += 2
        elif b == 0x68 and i+4 < len(data):
            v = struct.unpack_from("<I", data, i+1)[0]
            lines.append((off, rel_to_call, f"PUSH 0x{v:08x}")); i += 5
        else:
            i += 1
    return lines

def main():
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1
    import frida
    sess   = frida.get_local_device().attach(pid)
    scr    = sess.create_script(JS)
    ready  = {"v": False}
    def on_msg(m,_):
        if m.get("type")=="send" and m["payload"].get("t")=="ready": ready["v"]=True
        elif m.get("type")=="error": print("[ERR]", m.get("description"))
    scr.on("message", on_msg)
    scr.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    r = scr.exports_sync.dump()
    try: scr.unload(); sess.detach()
    except: pass

    if r.get("err"):
        print("[!] dump error:", r["err"]); return 1

    raw = bytes.fromhex(r["hex"].replace(" ",""))
    print(f"[+] PID={pid}  start={r['start_va']}  call_ret={r['call_ret_va']}  len={len(raw)}B")
    print()

    lines = decode(raw, 0, r["call_offset"])
    if not lines:
        print("  (no notable instructions found)")
    else:
        print(f"{'offset':>8}  {'rel_to_call':>12}  instruction")
        print("-"*65)
        for off, rel, txt in lines:
            marker = " ◄ CALL SITE" if rel == -5 else (" ← RET" if "RET" in txt else "")
            print(f"  +{off:04x}    {rel:+6d}  {txt}{marker}")

    # 专门列出所有 +0x50 写入
    print()
    subtype_hits = [(off, rel, txt) for off, rel, txt in lines if "SUBTYPE" in txt]
    if subtype_hits:
        print(f"=== 找到 {len(subtype_hits)} 处 +0x50 (subtype) 写入 ===")
        for off, rel, txt in subtype_hits:
            print(f"  offset +{off:04x}  rel_to_call {rel:+d}:  {txt}")
    else:
        print("=== 未在 ±512B 窗口内找到 +0x50 写入（subtype 可能在更远处或通过寄存器写入）===")

    return 0

if __name__ == "__main__":
    sys.exit(main())
