"""
在 PostSendMessageTask2 ctor 入口捕获完整调用栈（最多 8 层），
同时在 ctor 返回后 ~5ms 读取 this+0x50 的值（即实际写入的 subtype）。

用户依次发：文字 → 文件 → 图片 → silk
观察每种操作的调用栈差异，以及最终 subtype 值。
"""
import sys, time, json, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent

CTOR_RVA = 0x2b738a2

JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m=>m.name.toLowerCase()==='wxwork.exe');
const W0 = wx.base.toUInt32();
const ctorVA = (W0 + __CTOR_RVA__) >>> 0;
send({t:'ready', base:'0x'+W0.toString(16), ctor:'0x'+ctorVA.toString(16)});

let seq = 0;
const pending = {}; // seq -> {this_ptr, ts, stack}

Interceptor.attach(ptr(ctorVA), {
    onEnter: function(args){
        try {
            const id = ++seq;
            const thisPtr = this.context.ecx;

            // 抓调用栈（最多 10 帧）
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0,10);
            const stack = bt.map(va => {
                const rva = (va.toUInt32() - W0) >>> 0;
                return '0x' + rva.toString(16);
            });

            pending[id] = {this_ptr: thisPtr.toUInt32(), ts: Date.now(), stack, subtype: null};

            // 5ms 后读 +0x50（此时 subtype 应已被 caller 写入）
            setTimeout(function(){
                try {
                    const sub = thisPtr.add(0x50).readU8();
                    if (pending[id]) pending[id].subtype = sub;
                    send({t:'hit', id, this_ptr:'0x'+thisPtr.toUInt32().toString(16),
                          stack: pending[id].stack, subtype: sub});
                    delete pending[id];
                } catch(e){
                    send({t:'hit', id, this_ptr:'0x'+thisPtr.toUInt32().toString(16),
                          stack: stack, subtype: null, err: e.message});
                    delete pending[id];
                }
            }, 5);
        } catch(e){ send({t:'err_enter', msg:e.message}); }
    }
});
""".replace("__CTOR_RVA__", hex(CTOR_RVA))

def get_pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    import frida
    sess   = frida.get_local_device().attach(pid)
    scr    = sess.create_script(JS)
    ready  = {"v": False}
    events = []

    def on_msg(m,_):
        if m.get("type")=="send":
            p = m["payload"]
            if p.get("t")=="ready":
                ready["v"]=True
                print(f"[+] PID={pid}  wxbase={p['base']}  ctor={p['ctor']}")
            elif p.get("t")=="hit":
                events.append(p)
                sub = p.get("subtype")
                print(f"\n  [CTOR #{p['id']}]  this={p['this_ptr']}  subtype_after_5ms={sub}")
                for i, rva in enumerate(p.get("stack",[])):
                    print(f"    frame[{i}] {rva}")
            elif p.get("t") in ("err_enter","err"):
                print(f"  [ERR] {p.get('msg')}")
        elif m.get("type")=="error":
            print("[ERR]", m.get("description"))

    scr.on("message", on_msg)
    scr.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    print("="*65)
    print("Hook 就绪。请依次操作（每步等上面打印出 [CTOR] 后再做下一步）：")
    print("  步骤 1: 文件传输助手 → 发一条文字  'hi'")
    print("  步骤 2: 文件传输助手 → 拖一个 .txt 文件发送")
    print("  步骤 3: 文件传输助手 → 拖一张图片发送")
    print("  步骤 4: 文件传输助手 → 拖 silk 文件发送")
    print("  完成后等 10 秒，脚本自动退出并汇总")
    print("="*65)

    # 等待用户操作，最多 5 分钟
    t0 = time.time()
    while time.time() - t0 < 300:
        time.sleep(1)

    try: scr.unload(); sess.detach()
    except: pass

    print("\n" + "="*65)
    print(f"共捕获 {len(events)} 次 ctor 调用")
    sub_map = {}
    for e in events:
        sub = e.get("subtype")
        if sub not in sub_map: sub_map[sub] = []
        sub_map[sub].append(e.get("stack",[]))

    for sub, stacks in sorted(sub_map.items(), key=lambda kv: kv[0] or -1):
        print(f"\n  subtype={sub}  ({len(stacks)} 次)")
        for i, st in enumerate(stacks[:2]):
            print(f"    instance {i}:")
            for j, rva in enumerate(st[:6]):
                print(f"      frame[{j}] {rva}")

    out = OUT_DIR / f"ctor_stacks_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"pid":pid,"events":events},ensure_ascii=False,indent=2))
    print(f"\n[+] → {out.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
