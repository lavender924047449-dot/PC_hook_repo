# 手机语音同步到 PC 后：扫 Download task + 堆上 voice protobuf 字段
from __future__ import annotations
import json, re, subprocess, sys, time
from pathlib import Path
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
OUT = Path(r"d:\Only internship outputs\Test-Voice\runtime\wecom_re")

JS = r"""
'use strict';
const wx = Process.enumerateModules().filter(m=>m.name.toLowerCase()==='wxwork.exe')[0];
const W0 = wx.base.toUInt32();
const VTS = {
    DownloadFileTask2: W0+0xAB9F098,
    DownloadFtnFileTask: W0+0xAB9F88C,
    CdnCopyFileTask: W0+0xB48C768,
    HandleMessageResourcesTask: W0+0xABBACC4,
};
function u32(p){ try{return p.readU32();}catch(e){return 0;} }
function vtPat(vt){
    return [(vt)&255,((vt>>>8)&255),((vt>>>16)&255),((vt>>>24)&255)]
        .map(b=>b.toString(16).padStart(2,'0')).join(' ');
}
function scanVt(vt){
    const pat=vtPat(vt), hits=[];
    for(const r of Process.enumerateRanges({protection:'rw-',coalesce:false})){
        if(r.file) continue;
        let ms; try{ms=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
        for(const m of ms) hits.push(m.address.toString());
    }
    return hits;
}
function dumpTask(va){
    const p=ptr(va), out={va, strings:[], dwords:[]};
    for(let k=0;k<0x200/4;k++) out.dwords.push('0x'+u32(p.add(k*4)).toString(16));
    for(let off=0;off<0x200;off+=4){
        try {
            const size=u32(p.add(off+0x10)), cap=u32(p.add(off+0x14));
            if(size>0||cap>0){
                if(size>512||cap<size||cap>0x400000) continue;
                let dp=p.add(off);
                if(size>15) dp=ptr(u32(p.add(off)));
                const bytes=new Uint8Array(dp.readByteArray(Math.min(size,200)));
                let s=''; for(let i=0;i<bytes.length;i++){
                    const b=bytes[i]; s+=(b>=0x20&&b<=0x7e)?String.fromCharCode(b):'.';
                }
                if(s.replace(/\./g,'').length>=4)
                    out.strings.push({off:'0x'+off.toString(16),size,str:s});
            }
        }catch(e){}
    }
    return out;
}

// 扫目标 silk 文件名附近 ±8KB 找 md5/file_id
const TARGET = __TARGET_JSON__;
function scanNearSilk(){
    const pat = TARGET.split('').map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
    const hits=[];
    for(const r of Process.enumerateRanges({protection:'rw-',coalesce:false})){
        if(r.file) continue;
        let ms; try{ms=Memory.scanSync(r.base,r.size,pat);}catch(e){continue;}
        for(const m of ms.slice(0,20)){
            const base=m.address.sub(0x2000);
            let chunk; try{chunk=new Uint8Array(base.readByteArray(0x4000));}catch(e){continue;}
            let text=''; for(let i=0;i<chunk.length;i++){
                const b=chunk[i]; text+=(b>=0x20&&b<=0x7e)?String.fromCharCode(b):'\n';
            }
            const md5s=text.match(/[a-f0-9]{32}/g)||[];
            const uuids=text.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi)||[];
            hits.push({near:m.address.toString(), md5:md5s.slice(0,5), uuids:uuids.slice(0,5),
                context:text.slice(Math.max(0,text.indexOf(TARGET)-80), text.indexOf(TARGET)+120)});
        }
    }
    return hits;
}

const tasks={};
for(const k of Object.keys(VTS)) tasks[k]=scanVt(VTS[k]).map(va=>dumpTask(va));

send({tasks, near_silk: scanNearSilk()});
"""

def main():
    ref = OUT / "m3_voice_reference_20260913_210633.json"
    target = "2026_09_13_21_05_24_523.silk"
    if ref.is_file():
        silks = ref.read_text(encoding="utf-8")
        m = re.findall(r"2026_09_13_21_05_\d+_\d+\.silk", silks)
        if m: target = sorted(set(m))[-1]

    pid = int(subprocess.run(["powershell","-Command",
        "Get-Process WXWork -EA SilentlyContinue | Sort WS -Desc | Select -First 1 -Expand Id"],
        capture_output=True,text=True).stdout.strip())

    import frida
    js = JS.replace("__TARGET_JSON__", json.dumps(target))
    s = frida.get_local_device().attach(pid)
    sc = s.create_script(js)
    res={}
    sc.on('message', lambda m,_: res.update(m.get('payload',{})))
    sc.load(); time.sleep(1)
    sc.unload(); s.detach()

    out = OUT / "m3_received_voice_scan.json"
    out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[*] target silk: {target}")
    for k, arr in (res.get("tasks") or {}).items():
        print(f"\n[{k}] count={len(arr)}")
        for t in arr[:3]:
            print(f"  @{t['va']}")
            for s in t.get("strings",[])[:6]:
                print(f"    {s['off']} ({s['size']}B): {s['str'][:100]}")

    print(f"\n[near silk context]")
    for h in (res.get("near_silk") or [])[:5]:
        print(f"  md5={h.get('md5')} uuid={h.get('uuids')}")
        print(f"  ctx: {h.get('context','')[:200]}")

    print(f"\n→ {out.name}")

if __name__=="__main__":
    main()
