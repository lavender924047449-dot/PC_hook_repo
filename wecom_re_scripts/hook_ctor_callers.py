"""
运行时 hook PostSendMessageTask2 构造器候选，捕获每次调用者的 return address。
用户在窗口期内触发各种发送动作，脚本记录：
  - 每次 ctor 被调用的 caller RVA
  - 每个 caller 后续几十字节内的 MOV [reg+0x50], imm  ⇒ 该 caller 设置的 subtype
"""
import sys, time, json, subprocess, re
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent
CTOR_RVAS = [0x2b738a2, 0x2b74832]

JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
const W0 = wx.base.toUInt32();
const modEnd = wx.base.add(wx.size).toUInt32();
const CTOR_TARGETS = __CTORS__.map(rva => ({rva, va: (W0 + rva) >>> 0}));
send({t:'ready', base:'0x'+W0.toString(16), end:'0x'+modEnd.toString(16),
      targets: CTOR_TARGETS.map(t => 'ctor@rva '+ t.rva.toString(16))});

const hitLog = {}; // caller_rva → { count, contexts: [hex,...] }
const inThis = {}; // task_addr → { ctor_rva }

for (const t of CTOR_TARGETS){
    Interceptor.attach(ptr(t.va), {
        onEnter: function(args){
            try {
                const ret = this.returnAddress.toUInt32();
                if (ret < W0 || ret >= modEnd){
                    return; // caller outside wxwork.exe
                }
                const callerRva = (ret - W0) >>> 0;
                const key = '0x'+callerRva.toString(16);
                if (!hitLog[key]){
                    // dump 80 bytes forward from return address (=code AFTER the call)
                    let ctxHex = '';
                    try {
                        const raw = new Uint8Array(this.returnAddress.readByteArray(80));
                        for (let i=0;i<raw.length;i++) ctxHex += raw[i].toString(16).padStart(2,'0') + ' ';
                    } catch(e){}
                    // dump 32 bytes back (partial - to see the CALL instruction and before)
                    let backHex = '';
                    try {
                        const raw2 = new Uint8Array(this.returnAddress.sub(32).readByteArray(32));
                        for (let i=0;i<raw2.length;i++) backHex += raw2[i].toString(16).padStart(2,'0') + ' ';
                    } catch(e){}
                    hitLog[key] = {
                        count: 0,
                        ctor_rva: t.rva,
                        ctx_after_call: ctxHex.trim(),
                        ctx_before_call: backHex.trim()
                    };
                    send({t:'new_caller', caller_rva: key, ctor_rva:'0x'+t.rva.toString(16),
                          ctx_head: ctxHex.slice(0,60)});
                }
                hitLog[key].count += 1;
                // 记录 this pointer (ecx)
                const thisPtr = this.context.ecx;
                if (thisPtr && !thisPtr.isNull()){
                    inThis[thisPtr.toString()] = {ctor_rva: t.rva, caller_rva: callerRva, ts: Date.now()};
                }
            } catch(e){
                send({t:'err_onEnter', msg: e.message});
            }
        }
    });
}

rpc.exports = {
    snapshot: function(){
        return {hits: hitLog, tasks_seen: Object.keys(inThis).length};
    }
};
""".replace("__CTORS__", json.dumps(CTOR_RVAS))

# MOV [reg+0x50], imm patterns
BYTE_MOV_RE     = re.compile(r'\bc6\s+([4][0-7])\s+50\s+([0-9a-f]{2})\b', re.I)
DWORD_MOV_RE    = re.compile(r'\bc7\s+([4][0-7])\s+50\s+([0-9a-f]{2})\s+00\s+00\s+00\b', re.I)
BYTE_DISP32_RE  = re.compile(r'\bc6\s+([8][0-7])\s+50\s+00\s+00\s+00\s+([0-9a-f]{2})\b', re.I)
DWORD_DISP32_RE = re.compile(r'\bc7\s+([8][0-7])\s+50\s+00\s+00\s+00\s+([0-9a-f]{2})\s+00\s+00\s+00\b', re.I)
REG_MAP = {0:'eax',1:'ecx',2:'edx',3:'ebx',4:'esp',5:'ebp',6:'esi',7:'edi'}
def scan_subtype_writes(hex_str: str):
    out = []
    for pat, tag in [(BYTE_MOV_RE,'byte'),(DWORD_MOV_RE,'dword'),
                     (BYTE_DISP32_RE,'byte_d32'),(DWORD_DISP32_RE,'dword_d32')]:
        for m in pat.finditer(hex_str):
            modrm = int(m.group(1),16)
            reg = REG_MAP.get(modrm & 7, '?')
            imm = int(m.group(2),16)
            out.append({"kind":tag,"reg":reg,"imm":imm,"off":m.start()})
    return out

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    duration_s = int(sys.argv[1]) if len(sys.argv)>1 else 240
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(JS)
    ready = {"v": False}
    def on_msg(m,_):
        if m.get("type")=="send":
            p = m["payload"]
            if p.get("t")=="ready":
                ready["v"]=True
                print(f"[+] attached PID={pid}  wxbase={p['base']}..{p['end']}")
                for tg in p["targets"]: print(f"    hooking {tg}")
            elif p.get("t")=="new_caller":
                print(f"  [NEW caller] rva={p['caller_rva']}  ctor={p['ctor_rva']}")
                print(f"    ctx_after_call[0..30]={p['ctx_head']}")
            elif p.get("t")=="err_onEnter":
                print(f"  [ERR onEnter] {p.get('msg')}")
        elif m.get("type")=="error":
            print("[ERR]", m.get("description"))
    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print("="*70)
    print("请在", duration_s, "秒内触发以下操作（每步 15-30 秒）：")
    print("  1) 发一条文本消息 (例如 'hi')")
    print("  2) 拖一个文本文件 (.txt)")
    print("  3) 拖一张图片")
    print("  4) 拖 silk 文件")
    print("  5) 发个 emoji / 表情")
    print("  6) 如果 PC 上收到语音，尝试点播放（虽然是 receive 路径）")
    print("  7) 关注 [NEW caller] 打印 — 每个不同的 caller 通常对应一种消息类型")
    print("="*70)

    t0 = time.time()
    last_report = t0
    while time.time() - t0 < duration_s:
        time.sleep(1)
        if time.time() - last_report > 20:
            snap = script.exports_sync.snapshot()
            print(f"[+{int(time.time()-t0):>3}s] callers seen: {len(snap['hits'])}  tasks constructed: {snap['tasks_seen']}")
            last_report = time.time()

    snap = script.exports_sync.snapshot()
    try: script.unload(); session.detach()
    except Exception: pass

    print("\n" + "="*70)
    print(f"共发现 {len(snap['hits'])} 个不同 caller, {snap['tasks_seen']} 次构造")
    subtype_by_caller = {}
    for caller_rva, info in snap["hits"].items():
        findings = scan_subtype_writes(info["ctx_after_call"])
        info["subtype_writes"] = findings
        imms = [f["imm"] for f in findings]
        print(f"\n  caller {caller_rva}  count={info['count']}  ctor={info['ctor_rva']}")
        print(f"    ctx_after_call = {info['ctx_after_call'][:120]}...")
        if findings:
            summary = [f"0x{f['imm']:02x}({f['reg']},{f['kind']})" for f in findings]
            print(f"    subtype 写入: {summary}")
            for f in findings:
                subtype_by_caller.setdefault(f["imm"], []).append(caller_rva)
        else:
            print(f"    subtype 写入: (未在 +80B 内匹配到 MOV [reg+0x50], imm — 可能 imm 在更远处或经 reg 传递)")

    print(f"\n{'='*70}")
    print("按 subtype 汇总:")
    for imm in sorted(subtype_by_caller):
        callers = subtype_by_caller[imm]
        print(f"  subtype=0x{imm:02x} ({imm:>3})  ← 由 {len(callers)} 个 caller 写入: {callers[:5]}")

    out = OUT_DIR / f"hook_callers_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"pid":pid, "hits": snap["hits"]},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
