# m3_observe_voice_reference.py — 手机发真实语音 → PC 抓 voice 对照 layout
#
# 用法：脚本跑起来后，用手机企微给 PC【文件传输助手】发一条语音（5~10秒即可）
#
from __future__ import annotations
import argparse, json, subprocess, sys, time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
OUT_DIR = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

WATCH_VTS = {
    "PostSendMessageTask2": 0xABBB210,
    "HandleMessageResourcesTask": 0xABBACC4,
    "HandleForwardResourcesTask2": 0xABBA8C8,
    "CdnUploadFileTask": 0xB48CA88,
    "DownloadFileTask2": 0xAB9F098,
    "DownloadFtnFileTask": 0xAB9F88C,
}

FRIDA_JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const VTS = __VTS__;

function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function vtPat(vt){
    return [(vt)&255,((vt>>>8)&255),((vt>>>16)&255),((vt>>>24)&255)]
        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
}
function tryStdString(base){
    try {
        const size=u32(base.add(0x10)), cap=u32(base.add(0x14));
        if (size>0x2000||cap<size) return null;
        if (!size) return {size:0,str:''};
        const dp = size<=15 ? base : ptr(u32(base));
        const bytes = new Uint8Array(dp.readByteArray(size));
        let s=''; for(let i=0;i<size;i++) s+=String.fromCharCode(bytes[i]);
        return {size,cap,str:s};
    } catch(e){ return null; }
}
function dumpObj(va, n){
    const p=ptr(va), dwords=[], strings={};
    for(let k=0;k<n/4;k++) dwords.push('0x'+u32(p.add(k*4)).toString(16));
    for(let off=0;off+0x18<=n;off+=4){
        const s=tryStdString(p.add(off));
        if (s && s.size>0) strings['+0x'+off.toString(16)]=s;
        const pp=u32(p.add(off));
        if (pp>=0x10000){
            const sp=tryStdString(ptr(pp));
            if (sp && sp.size>0 && sp.size<512) strings['+0x'+off.toString(16)+'->str']=sp;
        }
    }
    let hex=''; try{ hex=Array.from(new Uint8Array(p.readByteArray(n)))
        .map(b=>b.toString(16).padStart(2,'0')).join(''); }catch(e){}
    return {va,dwords:dwords.slice(0,64),strings,hex:hex.slice(0,1024)};
}

function scanVt(vt){
    const pat=vtPat(vt), hits=[];
    for(const r of Process.enumerateRanges({protection:'rw-',coalesce:false})){
        if(r.file) continue;
        if(r.size<0x1000||r.size>0x8000000) continue;
        let ms; try{ms=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
        for(const m of ms) hits.push(m.address.toString());
    }
    return hits;
}

function scanSilkPaths(){
    const pat='43 3a 5c'; // C:\
    const found=[];
    for(const r of Process.enumerateRanges({protection:'rw-',coalesce:false})){
        if(r.file) continue;
        if(r.size<0x1000||r.size>0x10000000) continue;
        let ms; try{ms=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
        for(const m of ms.slice(0,200)){
            try {
                const s=m.address.readCString(200);
                if (s && s.indexOf('Cache\\Voice')>=0 && s.indexOf('.silk')>=0)
                    found.push(s.slice(0,180));
            } catch(e){}
        }
    }
    return found;
}

rpc.exports = {
    baseline: function(){
        const b={};
        for (const k of Object.keys(VTS)) b[k]=scanVt(VTS[k]);
        b.silk_paths = scanSilkPaths().slice(0,30);
        return b;
    },
    watch: function(ms, seenJson){
        const seen=JSON.parse(seenJson);
        const out={tasks:[], silk_new:[], packages:[]};
        const t0=Date.now();
        while(Date.now()-t0 < ms){
            for(const name of Object.keys(VTS)){
                for(const va of scanVt(VTS[name])){
                    const key=name+'@'+va;
                    if (seen[key]) continue;
                    seen[key]=true;
                    const sz = name.indexOf('Task2')>=0 || name==='PostSendMessageTask2' ? 0x100 : 0x200;
                    const d = dumpObj(va, sz);
                    d.class_name = name;
                    if (name==='PostSendMessageTask2'){
                        const pkg=u32(ptr(va).add(0x30));
                        if (pkg>=0x10000){
                            const pd=dumpObj(pkg, 512);
                            pd.role='package';
                            pd.subtype=u32(ptr(pkg).add(0x50));
                            out.packages.push(pd);
                            d.package_ptr='0x'+pkg.toString(16);
                            d.package_subtype=pd.subtype;
                        }
                    }
                    out.tasks.push(d);
                    send({t:'task', class_name:name, va, subtype:d.package_subtype});
                }
            }
            const paths=scanSilkPaths();
            for(const p of paths){
                if (!seen['silk:'+p]){ seen['silk:'+p]=true; out.silk_new.push(p);
                    send({t:'silk', path:p}); }
            }
        }
        return out;
    }
};
send({t:'ready'});
"""

def _pid():
    r=subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
        capture_output=True,text=True)
    return int(r.stdout.strip()) if r.stdout.strip() else None

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--wait", type=int, default=90)
    args=ap.parse_args()
    pid=args.pid or _pid()
    if not pid: print("[!] no WXWork"); return 1

    js=FRIDA_JS.replace("__VTS__", json.dumps(WATCH_VTS))
    import frida
    session=frida.get_local_device().attach(pid)
    script=session.create_script(js)
    ready={"v":False}; events=[]
    def on_msg(m,_):
        if m.get("type")=="send":
            p=m["payload"]
            if p.get("t")=="ready": ready["v"]=True
            elif p.get("t") in ("task","silk"):
                events.append(p)
                if p.get("t")=="task":
                    print(f"  [task] {p['class_name']} @{p['va']} subtype={p.get('subtype')}")
                else:
                    print(f"  [silk] {p['path'][:100]}")
        elif m.get("type")=="error":
            print("[ERR]", m.get("description"))
    script.on("message", on_msg)
    script.load()
    for _ in range(50):
        if ready["v"]: break
        time.sleep(0.1)

    print(f"[*] PID={pid}  baseline...")
    baseline=script.exports_sync.baseline()
    for k,v in baseline.items():
        if k=="silk_paths":
            print(f"    silk_paths: {len(v)}")
        else:
            print(f"    {k}: {len(v)}")

    print()
    print("="*70)
    print("  请用手机企微 → 给 PC【文件传输助手】发一条语音（5~10秒）")
    print(f"  {args.wait}s 窗口内脚本持续扫描...")
    print("="*70)

    t0=time.monotonic()
    result=script.exports_sync.watch(args.wait*1000, json.dumps(
        {f"{k}@{a}":True for k in WATCH_VTS for a in baseline.get(k,[])} |
        {f"silk:{p}":True for p in baseline.get("silk_paths",[])}
    ))
    print(f"[+] {time.monotonic()-t0:.1f}s")

    try: script.unload(); session.detach()
    except Exception: pass

    out={ "baseline":baseline, "result":result, "events":events,
          "staged": json.loads((OUT_DIR/"poc_staged_voice.json").read_text()) if (OUT_DIR/"poc_staged_voice.json").is_file() else {} }
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    path=OUT_DIR/f"m3_voice_reference_{ts}.json"
    path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n[+] tasks={len(result.get('tasks',[]))}  packages={len(result.get('packages',[]))}  new_silk={len(result.get('silk_new',[]))}")
    print(f"[+] → {path.name}")

    for pkg in result.get("packages") or []:
        print("\n=== PostSendMessageTask2 package (voice ref) ===")
        print(f"  subtype @+0x50 = {pkg.get('subtype')}")
        for off,s in (pkg.get("strings") or {}).items():
            print(f"  {off}: {s.get('str','')[:120]!r}")
        if pkg.get("hex"):
            print(f"  hex[:128] = {pkg['hex'][:128]}")

    if not result.get("packages") and result.get("silk_new"):
        print("\n[i] 未抓到 PostSendMessageTask2，但检测到新 silk（手机→PC 同步下载路径）")
        print("    将用 Download task + silk 路径做 voice protobuf 推断")

    return 0 if (result.get("packages") or result.get("silk_new")) else 1

if __name__=="__main__":
    sys.exit(main())
