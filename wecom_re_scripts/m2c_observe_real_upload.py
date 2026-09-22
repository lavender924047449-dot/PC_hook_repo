# m2c_observe_real_upload.py — 观察企微自身触发一次 CDN upload 时的真实 param/task 布局
#
# 用法：
#   1. 启动本脚本（--pid 21768，也可省略自动找）
#   2. 脚本进入 baseline 阶段（3s 扫堆记录当前 CdnUploadParam 数量）
#   3. 提示后，你在企微里操作：
#        - 打开文件传输助手 → 发一个小文件（.txt / .jpg / 任意）
#      也可以发图片。别发语音（PC 没这能力）
#   4. 脚本捕捉到新 CdnUploadParam / CdnUploadFileTask 时，dump 全部字段
#   5. 输出 → runtime/wecom_re/m2c_observe_result_*.json

from __future__ import annotations
import argparse, json, subprocess, sys, time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const VTS = {
    CdnUploadParam:    W0 + 0xB795B58,
    FtnUploadParam:    W0 + 0xB795BA0,
    CdnUploadFileTask: W0 + 0xB48CA88,
    BigCdnUploadTask:  W0 + 0xAB9D094,
    FtnUploadFileTask: W0 + 0xB48E308,
    FtnUploadFileTask2:W0 + 0xB48E688,
};

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function u8(p){ try{return p.readU8();}catch(e){return 0;} }
function inWx(v){ return v>=W0 && v<W0+wx.size; }

function vtPat(vt){
    return [(vt)&255,((vt>>>8)&255),((vt>>>16)&255),((vt>>>24)&255)]
        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
}

function scanHeap(vt){
    const pat = vtPat(vt);
    const hits = [];
    for (const r of Process.enumerateRanges({protection:'rw-', coalesce:false})){
        if (r.file) continue;
        if (r.size < 0x1000 || r.size > 0x8000000) continue;
        let ms; try{ ms=Memory.scanSync(r.base, r.size, pat);}catch(e){continue;}
        for (const m of ms) hits.push(m.address.toString());
    }
    return hits;
}

function tryStdString(base){
    try {
        const size = u32(base.add(0x10));
        const cap  = u32(base.add(0x14));
        if (size > 0x10000 || cap < size || cap > 0x400000) return null;
        if (size === 0){
            if (cap === 0 || cap === 15) return {kind:'empty', size:0, cap:cap, str:''};
            return null;
        }
        let dp;
        if (size <= 15){ dp = base; }
        else {
            const p = u32(base);
            if (p < 0x10000) return null;
            dp = ptr(p);
        }
        const bytes = new Uint8Array(dp.readByteArray(size));
        let s = '';
        for (let i = 0; i < size; i++){
            const b = bytes[i];
            s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
        }
        return {kind: size<=15?'sso':'heap', size:size, cap:cap, str:s};
    } catch(e){ return null; }
}

function dumpObject(va, size){
    const p = ptr(va);
    const dwords = [];
    for (let k = 0; k < size/4; k++) dwords.push('0x'+u32(p.add(k*4)).toString(16));
    // 尝试各 offset 作为 std::string / std::string*
    const strings = {};
    for (let off = 0; off + 0x18 <= size; off += 4){
        // std::string 内嵌
        const asStr = tryStdString(p.add(off));
        if (asStr && asStr.size > 0){
            strings['+0x'+off.toString(16)+' inline'] = asStr;
        }
        // std::string* 指针
        const pp = u32(p.add(off));
        if (pp >= 0x10000){
            const asPtr = tryStdString(ptr(pp));
            if (asPtr && asPtr.size > 0 && asPtr.size < 512){
                strings['+0x'+off.toString(16)+' ->str'] = asPtr;
            }
        }
    }
    return {va:va, dwords:dwords, strings:strings};
}

rpc.exports = {
    baseline: function(){
        const out = {ts: Date.now()};
        for (const k of Object.keys(VTS)) out[k] = scanHeap(VTS[k]);
        return out;
    },
    watch: function(durationMs, seenJson){
        const seen = JSON.parse(seenJson);
        const seenSet = {};
        for (const k of Object.keys(VTS)){
            seenSet[k] = {};
            for (const a of (seen[k]||[])) seenSet[k][a] = true;
        }
        const dumps = {};
        for (const k of Object.keys(VTS)) dumps[k] = [];

        const t0 = Date.now();
        while (Date.now() - t0 < durationMs){
            for (const k of Object.keys(VTS)){
                for (const va of scanHeap(VTS[k])){
                    if (seenSet[k][va]) continue;
                    seenSet[k][va] = true;
                    const size = k.indexOf('Task')>=0 ? 0x200 : 0x40;
                    const d = dumpObject(va, size);
                    dumps[k].push(d);
                    send({t:'new_'+k, va, dwords: d.dwords.slice(0,12), strings: d.strings});
                }
            }
        }
        return dumps;
    },
    // 观察 WinMember+0x60 registry 内容变化
    dumpRegistry: function(){
        const win = ptr('0x2b5983c0');
        return dumpObject(win.add(0x60).toString(), 0x100);
    }
};
send({t:'ready'});
"""

def _pid():
    r = subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
        capture_output=True, text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--wait", type=int, default=60, help="give user N seconds to send file")
    ap.add_argument("--auto", action="store_true", help="skip prompt, watch immediately")
    args = ap.parse_args()

    pid = args.pid or _pid()
    if not pid:
        print("[!] no WXWork.exe"); return 1

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}
    events = []
    def on_msg(m, _d):
        if m.get("type") == "send":
            p = m["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t","").startswith("new_"):
                events.append(p)
                print(f"  [!!] {p['t']} @ {p['va']}")
                if p.get('strings'):
                    for k, v in list(p['strings'].items())[:5]:
                        s = v.get('str','')[:100]
                        print(f"       {k}: size={v.get('size')} {s!r}")
        elif m.get("type") == "error":
            print("  [ERR]", m.get("description"))
    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print(f"[*] attached PID={pid}")
    baseline = script.exports_sync.baseline()
    print(f"[*] baseline:")
    for k, v in baseline.items():
        if k == 'ts': continue
        print(f"    {k}: {len(v)}")
    reg_before = script.exports_sync.dump_registry()

    if not args.auto:
        print()
        print("=" * 70)
        print("  请你现在在企微 PC 里操作：")
        print("    1) 打开【文件传输助手】")
        print("    2) 拖入一个小文件（.txt / .jpg / 任意，几十 KB 就够）")
        print("    3) 点发送")
        print(f"  {args.wait} 秒内脚本会持续扫描堆抓取真实 CdnUploadParam")
        print("=" * 70)
        input("  准备好按 Enter 开始观察...")

    print(f"\n[*] watching {args.wait}s ...")
    t0 = time.monotonic()
    dumps = script.exports_sync.watch(args.wait * 1000, json.dumps(baseline))
    reg_after = script.exports_sync.dump_registry()
    print(f"[+] {time.monotonic()-t0:.1f}s")

    try: script.unload(); session.detach()
    except Exception: pass

    result = {
        "pid": pid,
        "baseline": baseline,
        "dumps": dumps,
        "events": events,
        "registry_before": reg_before,
        "registry_after": reg_after,
    }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m2c_observe_result_{ts}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] {len(dumps['params'])} new params, {len(dumps['tasks'])} new tasks, {len(dumps['bigs'])} bigs")
    print(f"[+] → {out.name}")

    total = sum(len(v) for v in dumps.values())
    print(f"\n[+] total new objects: {total}")
    for k, arr in dumps.items():
        print(f"    {k}: {len(arr)}")
    if total == 0:
        print("[!] 未观察到新对象。可能：")
        print("    - 你没在时间窗内发送")
        print("    - 试试重新发一次，发大点的文件（几 MB）")
        return 1

    for k in ['CdnUploadParam','FtnUploadParam','CdnUploadFileTask','FtnUploadFileTask','FtnUploadFileTask2','BigCdnUploadTask']:
        arr = dumps.get(k, [])
        if not arr: continue
        print("\n" + "=" * 70)
        print(f"  {k} 真实布局（首个新对象）:")
        print("=" * 70)
        p = arr[0]
        for i, dw in enumerate(p['dwords'][:32]):
            print(f"  +0x{i*4:02x}: {dw}")
        print("  字符串字段:")
        for kk, v in p['strings'].items():
            print(f"    {kk}: size={v['size']} {v['str'][:140]!r}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
