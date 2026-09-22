"""
验证：patch 写入 +0x1b8 voice proto 后，CDN 上传完成是否会覆写它。
策略：patch 后每 2s 重读同一 task 的 +0x1b8 内容，持续 60s，报告变化。
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
send({t:'ready', base:'0x'+W0.toString(16)});

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function u8(p){  try{return p.readU8();}catch(e){return 0;}  }
function hex2(b){ return b.toString(16).padStart(2,'0'); }

// 读 std::string 摘要
function readStrSummary(base){
    const ptr0 = u32(base), sz = u32(base.add(0x10)), cap = u32(base.add(0x14));
    let first8 = '';
    try{
        const dp = sz<=15 ? base : ptr(ptr0);
        const bytes = new Uint8Array(dp.readByteArray(Math.min(sz,16)));
        first8 = Array.from(bytes).map(hex2).join(' ');
    }catch(e){}
    return {ptr:'0x'+ptr0.toString(16), sz, cap, first8};
}

// vtable pattern
function vtPat(va){
    return [(va)&255,(va>>8&255),(va>>16&255),(va>>24&255)].map(b=>b.toString(16).padStart(2,'0')).join(' ');
}

// 找一个 FILE task (subtype=8) → 记录 task 地址
rpc.exports = {
    findFileTask: function(){
        const pat = vtPat(VT_VA);
        const seen = {};
        const t0 = Date.now();
        while(Date.now()-t0 < 30000){
            for(const r of Process.enumerateRanges({protection:'rw-',coalesce:false})){
                if(r.file||r.size<0x1000||r.size>0x8000000) continue;
                let ms; try{ms=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
                for(const m of ms){
                    const task=m.address;
                    if(seen[task.toString()]) continue;
                    seen[task.toString()]=true;
                    const pkgPtr=u32(task.add(0x30));
                    if(!pkgPtr||pkgPtr<0x10000) continue;
                    const pkg=ptr(pkgPtr);
                    const subtype=u8(pkg.add(0x50));
                    if(subtype!==8&&subtype!==15) continue; // only file tasks
                    const conv_ptr=u32(pkg.add(0x28));
                    if(!conv_ptr) continue;
                    // return task info
                    const s1b8 = readStrSummary(pkg.add(0x1b8));
                    return {found:true, task:'0x'+task.toUInt32().toString(16),
                            pkg:'0x'+pkgPtr.toString(16), subtype,
                            str_1b8: s1b8};
                }
            }
            Thread.sleep(0.05);
        }
        return {found:false};
    },

    // 对给定 task 打快照 +0x50/+0x1b8 状态
    snapshot: function(task_va, pkg_va){
        const task = ptr(task_va);
        const pkg  = ptr(pkg_va);
        const subtype = u8(pkg.add(0x50));
        const s1b8 = readStrSummary(pkg.add(0x1b8));
        // raw bytes 0x1b0..0x1d0
        let raw='';
        try{raw=Array.from(new Uint8Array(pkg.add(0x1b0).readByteArray(32))).map(hex2).join(' ');}catch(e){}
        return {ts: Date.now(), subtype, str_1b8: s1b8, raw_1b0: raw};
    },

    // patch +0x50 subtype → 2 and write minimal 11B SSO voice proto
    patchTask: function(task_va, pkg_va){
        const pkg = ptr(pkg_va);
        // patch subtype
        pkg.add(0x50).writeU8(2);
        // write minimal 11B SSO voice proto at +0x1b8
        const pb = [0x0a,0x09,0x08,0x00,0x12,0x05,0x0a,0x03,0x31,0x32,0x33];
        for(let i=0;i<pb.length;i++) pkg.add(0x1b8+i).writeU8(pb[i]);
        pkg.add(0x1c8).writeU32(11);
        pkg.add(0x1cc).writeU32(15);
        return {patched:true, subtype_now: pkg.add(0x50).readU8()};
    }
};
""".replace("__VT_RVA__", hex(POST_SEND_VT))

def get_pid():
    r = subprocess.run(["powershell", "-Command",
        "Get-Process WXWork -EA SilentlyContinue|Sort WS -Desc|Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main():
    pid = get_pid()
    if not pid: print("[!] no WXWork"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script  = session.create_script(JS)
    ready   = {"v": False}
    def on_msg(m, _d):
        if m.get("type")=="send" and m["payload"].get("t")=="ready": ready["v"]=True
        elif m.get("type")=="error": print("[ERR]", m.get("description"))
    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print(f"[*] PID={pid}  等待 FILE task（30s 窗口）... 请拖 silk 当文件发送")
    r = script.exports_sync.find_file_task()
    if not r.get("found"):
        print("[!] 未找到 file task"); return 1

    task_va = r["task"]
    pkg_va  = r["pkg"]
    print(f"[+] found FILE task={task_va} pkg={pkg_va} subtype={r['subtype']}")
    print(f"    +0x1b8: {r['str_1b8']}")

    # 0 号快照（patch 前）
    snaps = [script.exports_sync.snapshot(task_va, pkg_va)]
    snaps[-1]["label"] = "before_patch"
    print(f"\n[T+0s] before patch: subtype={snaps[-1]['subtype']}  +0x1b8={snaps[-1]['str_1b8']}")

    # patch
    pr = script.exports_sync.patch_task(task_va, pkg_va)
    print(f"[*] patch: {pr}")

    # 每 2s 重读 60s
    for i in range(1, 31):
        time.sleep(2)
        s = script.exports_sync.snapshot(task_va, pkg_va)
        s["label"] = f"t+{i*2}s"
        snaps.append(s)
        prev_sz = snaps[-2]["str_1b8"]["sz"]
        curr_sz = s["str_1b8"]["sz"]
        changed = "*** CHANGED ***" if s["str_1b8"] != snaps[1]["str_1b8"] else ""
        print(f"[T+{i*2}s] subtype={s['subtype']}  sz={curr_sz}  first8={s['str_1b8']['first8']}  {changed}")

    try: script.unload(); session.detach()
    except Exception: pass

    out = OUT_DIR / "patch_survival.json"
    out.write_text(json.dumps({"task":task_va,"pkg":pkg_va,"snapshots":snaps},
                               ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out.name}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
