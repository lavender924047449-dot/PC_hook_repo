"""
subtype 全景侦察：长时间监视所有 PostSendMessageTask2 实例，穷举 subtype 分布。

在窗口期用户请依次触发以下操作，脚本会记录每个 subtype 首次/末次出现：
  1) 发一条文本消息
  2) 拖一个文件 (非 silk)
  3) 拖一张图片
  4) 拖 silk (受 M3 影响，subtype=15)
  5) 从手机转发一条语音到 PC 的会话
  6) 如果 PC 上能预览语音，播放它
  7) 尝试任何看起来像"发送语音"的操作
"""
import sys, time, json, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(__file__).resolve().parent
POST_SEND_VT = 0xABBB210

JS = r"""
'use strict';
const wx = Process.enumerateModules().find(m => m.name.toLowerCase() === 'wxwork.exe');
const W0 = wx.base.toUInt32();
const VT_VA = (W0 + __VT_RVA__) >>> 0;
send({t:'ready', vtable_va:'0x'+VT_VA.toString(16)});

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function u8(p){  try{return p.readU8();}catch(e){return 0;}  }
function hex2(b){ return b.toString(16).padStart(2,'0'); }

function readStdString(base){
    try {
        const sz = u32(base.add(0x10));
        if (sz > 0x400) return '';
        const cap = u32(base.add(0x14));
        const dp = (sz <= 15 || cap === 15) ? base : ptr(u32(base));
        const raw = new Uint8Array(dp.readByteArray(Math.min(sz, 128)));
        let s = '';
        for (let i=0;i<raw.length;i++){
            const c = raw[i];
            if (c < 32 || c > 126){ if (c===0) break; s += '.'; }
            else s += String.fromCharCode(c);
        }
        return s;
    } catch(e){ return ''; }
}

function vtPat(va){
    return [(va)&255,(va>>8&255),(va>>16&255),(va>>24&255)].map(b=>b.toString(16).padStart(2,'0')).join(' ');
}

let running = false;
let stats = null;     // {subtype: {count, first_ts, last_ts, samples:[{...}]}}
const seenTasks = {}; // task_addr → true

function scanOnce(){
    const pat = vtPat(VT_VA);
    for (const r of Process.enumerateRanges({protection:'rw-', coalesce:false})){
        if (r.file) continue;
        if (r.size < 0x1000 || r.size > 0x8000000) continue;
        let ms; try{ ms=Memory.scanSync(r.base, r.size, pat);}catch(e){continue;}
        for (const m of ms){
            const task = m.address;
            const key = task.toString();
            if (seenTasks[key]) continue;
            seenTasks[key] = true;
            const pkgPtr = u32(task.add(0x30));
            if (!pkgPtr || pkgPtr < 0x10000) continue;
            const pkg = ptr(pkgPtr);
            const subtypeByte = u8(pkg.add(0x50));
            const conv = readStdString(pkg.add(0x28));
            const clientMsgId = readStdString(pkg.add(0x10));
            // sniff body at +0x1b8 (first 64 bytes)
            let bodyHex = '';
            try {
                const bsz = u32(pkg.add(0x1c8));
                const bptr = u32(pkg.add(0x1b8));
                const bcap = u32(pkg.add(0x1cc));
                let dp;
                if (bsz > 0 && bsz <= 15) dp = pkg.add(0x1b8);
                else if (bcap === 15 && bsz <= 15) dp = pkg.add(0x1b8);
                else if (bptr > 0x10000) dp = ptr(bptr);
                if (dp){
                    const raw = new Uint8Array(dp.readByteArray(Math.min(bsz||64, 64)));
                    bodyHex = Array.from(raw).map(hex2).join('');
                }
            } catch(e){}

            const k = ''+subtypeByte;
            if (!stats[k]){
                stats[k] = {count:0, first_ts:Date.now(), last_ts:Date.now(), samples:[]};
            }
            stats[k].count += 1;
            stats[k].last_ts = Date.now();
            if (stats[k].samples.length < 3){
                stats[k].samples.push({
                    task: key, pkg: pkgPtr.toString(16),
                    conv: conv, clientMsgId: clientMsgId,
                    body_first64_hex: bodyHex,
                    body_sz: u32(pkg.add(0x1c8)),
                    off54_hex: (function(){
                        try{
                            const b=new Uint8Array(pkg.add(0x54).readByteArray(4));
                            return Array.from(b).map(hex2).join('');
                        }catch(e){return '';}
                    })(),
                    ts: Date.now()
                });
                send({t:'new_subtype', subtype: subtypeByte, conv, clientMsgId,
                      body_head: bodyHex.slice(0,64), off54: stats[k].samples[stats[k].samples.length-1].off54_hex});
            }
        }
    }
}

rpc.exports = {
    start: function(){
        running = true;
        stats = {};
        for (const k in seenTasks) delete seenTasks[k];
    },
    tick: function(){
        if (!running) return null;
        scanOnce();
        return stats;
    },
    stop: function(){
        running = false;
        return stats;
    }
};
""".replace("__VT_RVA__", hex(POST_SEND_VT))

def get_pid():
    r = subprocess.run(["powershell", "-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    duration_s = int(sys.argv[1]) if len(sys.argv)>1 else 300
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(JS)
    ready = {"v": False}
    def on_msg(m,_):
        if m.get("type")=="send":
            p=m["payload"]
            if p.get("t")=="ready":
                ready["v"]=True
                print(f"[+] attached PID={pid}  vtable={p['vtable_va']}")
            elif p.get("t")=="new_subtype":
                print(f"  [!!! NEW subtype={p['subtype']}]  conv={p.get('conv','')[:40]!r} "
                      f"clientMsgId={p.get('clientMsgId','')[:40]!r}  off54={p.get('off54')}")
                print(f"      body[0:64]={p.get('body_head')}")
        elif m.get("type")=="error":
            print("[ERR]",m.get("description"))
    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print("="*70)
    print("请依次触发以下操作（每步间隔 15-30 秒）：")
    print("  1) 在文件传输助手发一条文本 (例如 'hi')")
    print("  2) 拖一个普通文件（非 silk，非图片，比如 .txt）")
    print("  3) 拖一张图片")
    print("  4) 拖 silk 文件")
    print("  5) 从手机转发一条语音消息到 PC 的会话（PC 接收）")
    print("  6) 如果 PC 上能预览这条语音，播放它")
    print("  7) 观察下方 [!!! NEW subtype=X] 打印")
    print(f"  8) {duration_s}s 后自动结束并汇总")
    print("="*70)

    script.exports_sync.start()
    t0 = time.time()
    last_print = t0
    while time.time() - t0 < duration_s:
        stats = script.exports_sync.tick()
        now = time.time()
        if now - last_print >= 15:
            elapsed = int(now - t0)
            distr = {k: v["count"] for k,v in (stats or {}).items()}
            print(f"[+{elapsed:03d}s] subtype 分布: {distr}")
            last_print = now
        time.sleep(0.1)

    stats = script.exports_sync.stop()
    try: script.unload(); session.detach()
    except Exception: pass

    print("\n" + "="*70)
    print("最终 subtype 统计:")
    for k, v in sorted((stats or {}).items(), key=lambda kv:int(kv[0])):
        print(f"  subtype={k:>3}: count={v['count']}  首次={time.strftime('%H:%M:%S', time.localtime(v['first_ts']/1000))}"
              f"  末次={time.strftime('%H:%M:%S', time.localtime(v['last_ts']/1000))}")

    out = OUT_DIR / f"subtype_survey_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps({"pid":pid,"duration_s":duration_s,"stats":stats},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
