# dump_cdn_upload_task.py — M2b · CDN 上传 Task 堆布局 dump
# =============================================================================
#
# 目标：在语音 CDN 上传期间，扫堆定位 CdnUploadFileTask / BigCdnUploadFileTask，
# dump 对象内 std::string 字段（尤其 Cache\Voice\*.silk 路径、conv_id）。
#
# 用法：
#   # 空闲 baseline（应 0 或极少命中）
#   python runtime/wecom_re/dump_cdn_upload_task.py --duration 10
#
#   # 校准：手机给 FTA 发一条语音，脚本跑满 duration
#   python runtime/wecom_re/dump_cdn_upload_task.py --duration 60
#
# 严格约束：只读 attach，禁止 Interceptor。
# =============================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

# 导入同目录常量（直接运行脚本时 sys.path 含脚本目录）
from cdn_task_constants import CDN_UPLOAD_VTABLES  # noqa: E402

TASK_DUMP_BYTES = 0x600
PACKAGE_DUMP_BYTES = 0x300

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base;
send({t:'info', msg:'wx base=' + WXBASE});

const TASK_DUMP = __TASK_DUMP__;
const PACKAGE_DUMP = __PACKAGE_DUMP__;

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function b2hex(bytes){
    if (!bytes) return '';
    const u = new Uint8Array(bytes);
    const s = [];
    for (let i = 0; i < u.length; i++)
        s.push(u[i].toString(16).padStart(2, '0'));
    return s.join('');
}
function isReadable(p, len){
    try { p.readByteArray(len); return true; }
    catch(e){ return false; }
}

function tryStdString(base){
    let ptrOrSso, size, cap;
    try {
        ptrOrSso = u32(base);
        size = u32(base.add(0x10));
        cap  = u32(base.add(0x14));
    } catch(e){ return null; }
    if (size > 0x10000 || cap > 0x400000 || cap < size) return null;
    if (size === 0){
        if (cap === 0 || cap === 15) return {kind:'empty', size:0, cap:cap, str_utf8:''};
        return null;
    }
    if (size <= 15){
        let bytes;
        try { bytes = new Uint8Array(base.readByteArray(16)); }
        catch(e){ return null; }
        let s = '';
        for (let i = 0; i < size; i++) s += String.fromCharCode(bytes[i]);
        return {kind:'sso', size:size, cap:cap, str_utf8:s, str_obj: base.toString()};
    }
    if (ptrOrSso < 0x10000 || !isReadable(ptr(ptrOrSso), size)) return null;
    const bytes = ptr(ptrOrSso).readByteArray(size);
    let s = '';
    try {
        const u = new Uint8Array(bytes);
        for (let i = 0; i < u.length; i++){
            const b = u[i];
            if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) s += '?';
            else if (b <= 0x7e) s += String.fromCharCode(b);
            else s += '?';
        }
    } catch(e){}
    return {kind:'heap', size:size, cap:cap, ptr:'0x'+ptrOrSso.toString(16),
            str_utf8:s, str_obj: base.toString(), data_ptr:'0x'+ptrOrSso.toString(16)};
}

function scanStringCandidates(base, len){
    const out = [];
    for (let off = 0; off + 0x18 <= len; off += 4){
        const s = tryStdString(base.add(off));
        if (s && s.kind !== 'empty' && s.size >= 1) out.push({off:'0x'+off.toString(16), ...s});
    }
    return out;
}

function readRaw(base, len){
    try { return b2hex(base.readByteArray(len)); }
    catch(e){ return null; }
}

function readDwords(base, len){
    const out = [];
    for (let off = 0; off < len; off += 4){
        let v;
        try { v = u32(base.add(off)); } catch(e){ v = 0; }
        let hint = 'int';
        if (v >= 0x10000 && v < 0x80000000 && isReadable(ptr(v), 4)) hint = 'ptr';
        out.push({off:'0x'+off.toString(16), u32:v, hex:'0x'+v.toString(16), hint:hint});
    }
    return out;
}

function isVoiceRelated(s){
    if (!s) return false;
    const t = s.str_utf8 || '';
    return t.indexOf('.silk') >= 0 || t.indexOf('Cache\\Voice') >= 0 ||
           t.indexOf('Cache/Voice') >= 0 || t.indexOf('FILEASSIST') >= 0 ||
           (t.indexOf('S:') === 0 && t.length >= 20);
}

function vtBytesFromRva(rva){
    const vtVA = WXBASE.add(rva).toUInt32();
    return [
        (vtVA & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 8) & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 16) & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 24) & 0xff).toString(16).padStart(2, '0')
    ].join(' ');
}

function dumpTaskHit(taskAddr, className, vtableRva){
    const rec = {
        task_addr: taskAddr.toString(),
        class_name: className,
        vtable_rva: '0x' + vtableRva.toString(16),
        task_hex: readRaw(taskAddr, TASK_DUMP),
        task_dwords: readDwords(taskAddr, TASK_DUMP),
        task_strings: scanStringCandidates(taskAddr, TASK_DUMP),
        voice_strings: [],
    };
    for (let i = 0; i < rec.task_strings.length; i++){
        if (isVoiceRelated(rec.task_strings[i])) rec.voice_strings.push(rec.task_strings[i]);
    }
    // 也扫 task+0x30 指向的 package（若存在）
    const pkgPtr = u32(taskAddr.add(0x30));
    rec.pkg_ptr = pkgPtr ? '0x' + pkgPtr.toString(16) : 'null';
    if (pkgPtr && pkgPtr >= 0x10000 && isReadable(ptr(pkgPtr), PACKAGE_DUMP)){
        const pkg = ptr(pkgPtr);
        rec.pkg_strings = scanStringCandidates(pkg, PACKAGE_DUMP);
        rec.pkg_voice_strings = [];
        for (let i = 0; i < rec.pkg_strings.length; i++){
            if (isVoiceRelated(rec.pkg_strings[i])) rec.pkg_voice_strings.push(rec.pkg_strings[i]);
        }
    }
    return rec;
}

rpc.exports = {
    scanLoop: function(specJson, durationMs){
        const spec = JSON.parse(specJson);
        const targets = spec.targets;
        const patterns = [];
        for (let i = 0; i < targets.length; i++){
            patterns.push({
                name: targets[i].name,
                rva: targets[i].rva,
                bytes: vtBytesFromRva(targets[i].rva),
            });
        }
        const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        const seen = {};
        const events = [];
        let scans = 0;
        const t0 = Date.now();
        const deadline = t0 + durationMs;
        while (Date.now() < deadline){
            scans++;
            for (let p = 0; p < patterns.length; p++){
                const pat = patterns[p];
                for (let i = 0; i < ranges.length; i++){
                    const r = ranges[i];
                    let ms;
                    try { ms = Memory.scanSync(r.base, r.size, pat.bytes); }
                    catch(e){ continue; }
                    for (let j = 0; j < ms.length; j++){
                        const taskAddr = ms[j].address;
                        const key = pat.name + '@' + taskAddr.toString();
                        if (seen[key]) continue;
                        const rec = dumpTaskHit(taskAddr, pat.name, pat.rva);
                        seen[key] = rec;
                        events.push({
                            t_ms: Date.now() - t0,
                            scan: scans,
                            class_name: pat.name,
                            task_addr: rec.task_addr,
                            n_voice_strings: rec.voice_strings.length,
                            voice_preview: rec.voice_strings.length ?
                                rec.voice_strings[0].str_utf8.slice(0, 120) : '',
                        });
                    }
                }
            }
        }
        const tasks = [];
        for (const k in seen) tasks.push(seen[k]);
        return {scans, duration_ms: Date.now()-t0, tasks, events};
    },

    scanOnce: function(specJson){
        const spec = JSON.parse(specJson);
        const targets = spec.targets;
        const patterns = [];
        for (let i = 0; i < targets.length; i++){
            patterns.push({
                name: targets[i].name,
                rva: targets[i].rva,
                bytes: vtBytesFromRva(targets[i].rva),
            });
        }
        const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        const tasks = [];
        for (let p = 0; p < patterns.length; p++){
            const pat = patterns[p];
            for (let i = 0; i < ranges.length; i++){
                const r = ranges[i];
                let ms;
                try { ms = Memory.scanSync(r.base, r.size, pat.bytes); }
                catch(e){ continue; }
                for (let j = 0; j < ms.length; j++){
                    tasks.push(dumpTaskHit(ms[j].address, pat.name, pat.rva));
                }
            }
        }
        return {tasks: tasks, n: tasks.length};
    }
};
send({t:'ready'});
"""


def _find_wxwork_pid() -> int | None:
    r = subprocess.run(
        ["powershell", "-Command",
         "Get-Process WXWork -ErrorAction SilentlyContinue | "
         "Sort-Object WorkingSet64 -Descending | "
         "Select-Object -First 1 -ExpandProperty Id"],
        capture_output=True, text=True, encoding="utf-8",
    )
    s = r.stdout.strip()
    return int(s) if s else None


def _build_vtable_spec() -> list[dict[str, Any]]:
    return [{"name": n, "rva": rva} for n, rva in CDN_UPLOAD_VTABLES.items()]


def _attach_script(pid: int):
    import frida
    js = (FRIDA_JS
          .replace("__TASK_DUMP__", str(TASK_DUMP_BYTES))
          .replace("__PACKAGE_DUMP__", str(PACKAGE_DUMP_BYTES)))
    session = frida.get_local_device().attach(pid)
    script = session.create_script(js)
    ready = {"v": False}

    def on_message(msg, _data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "info":
                print(f"    [js] {p['msg']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)
    return session, script


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="dump CdnUploadFileTask heap layout")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=45,
                    help="scan duration seconds (0 = single snapshot)")
    ap.add_argument("--label", default="", help="output label suffix")
    args = ap.parse_args(argv)

    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe running")
        return 1
    print(f"[*] target PID={pid}")

    vtables = _build_vtable_spec()
    vt_desc = ", ".join(f"{v['name']}=0x{v['rva']:x}" for v in vtables)
    print(f"[*] vtables: {vt_desc}")

    session, script = _attach_script(pid)
    spec = json.dumps({"targets": vtables})

    if args.duration <= 0:
        print("[*] single snapshot scan...")
        result = script.exports_sync.scan_once(spec)
        result["mode"] = "snapshot"
    else:
        print(f"[*] JS tight-loop scan for {args.duration}s")
        print("[i] 若做校准：在脚本运行期间触发一条语音 CDN 上传（手机→FTA 亦可）")
        result = script.exports_sync.scan_loop(spec, args.duration * 1000)
        result["mode"] = "loop"

    result["pid"] = pid
    result["vtables"] = vtables

    try:
        script.unload()
        session.detach()
    except Exception:
        pass

    tasks = result.get("tasks") or []
    events = result.get("events") or []
    voice_hits = [t for t in tasks if t.get("voice_strings")]

    print()
    print("=" * 70)
    print(f"[+] mode={result['mode']}  tasks={len(tasks)}  voice_related={len(voice_hits)}")
    for ev in events:
        print(f"  [+{ev.get('t_ms', 0)/1000:5.1f}s] {ev.get('class_name')} "
              f"@{ev.get('task_addr')} voice_str={ev.get('n_voice_strings')} "
              f"{ev.get('voice_preview', '')[:80]}")

    for t in voice_hits[:5]:
        print(f"\n  ★ {t['class_name']} @{t['task_addr']}")
        for vs in t.get("voice_strings") or []:
            print(f"      off={vs.get('off')} kind={vs.get('kind')} "
                  f"size={vs.get('size')} str={vs.get('str_utf8', '')[:100]}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    label = f"_{args.label}" if args.label else ""
    out_path = OUT_DIR / f"cdn_upload_dump{label}_{ts}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] → {out_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
