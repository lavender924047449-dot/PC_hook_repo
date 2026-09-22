# m2c_invoke_cdn_upload.py — M2c 执行：NativeFunction 调 FileService::CdnUploadFile
# =============================================================================
# 2026-09-13 实证（wx 5.0.10.6015 · PID 21768 · base 0x1c0000）：
#   FileService 单例 heap vtable=0xab69924
#   CdnUploadFile = vtable slot[2] RVA 0x2499bb0 (thiscall, ret 0xC)
#   CdnUploadParam = 0x2C bytes（非 FtnUploadParam）
#   0xA08B00 = FtnUploadParam::InitFromDefault（勿用于 CdnUploadFile）
#   +0x10 = path 指针（type5: mov eax,[param+0x10]），+0x1c = file_type
#   file_type @ +0x1c；5 → voice/type5 handler 0x249cf20
#
# 禁止 Interceptor。只允许 NativeFunction + 只读扫堆 + 定长 heap 写。
#
# 用法：
#   python runtime/wecom_re/m2c_invoke_cdn_upload.py --dry-run
#   python runtime/wecom_re/m2c_invoke_cdn_upload.py --to-conv FILEASSIST
#   python runtime/wecom_re/m2c_invoke_cdn_upload.py run --silk path/to.voice.silk
# =============================================================================

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"

from cdn_task_constants import (  # noqa: E402
    CDN_UPLOAD_VTABLES,
    M2C,
    POST_SEND_MESSAGE_TASK2,
    WATCH_VTABLES,
)
from poc_voice_cdn_inject import (  # noqa: E402
    _find_wxwork_pid,
    _resolve_staged_silk,
    stage_silk,
)

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WX = wx.base;
const W0 = WX.toUInt32();
const SZ = wx.size;
send({t:'info', msg:'wx base=' + WX});

const CFG = __CFG__;

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function cstr(p,n){ try { return p.readCString(n||256); } catch(e){ return null; } }

function vtPat(rva){
    const v = W0 + rva;
    return [(v&255),((v>>>8)&255),((v>>>16)&255),((v>>>24)&255)]
        .map(function(b){ return b.toString(16).padStart(2,'0'); }).join(' ');
}

function heapSingleton(vtableRva){
    const pat = vtPat(vtableRva);
    const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
    const hits = [];
    for (let i = 0; i < ranges.length; i++){
        const r = ranges[i];
        if (r.file) continue;
        if (r.size < 0x1000 || r.size > 0x8000000) continue;
        let ms;
        try { ms = Memory.scanSync(r.base, r.size, pat); } catch(e){ continue; }
        for (let j = 0; j < ms.length; j++) hits.push(ms[j].address.toString());
    }
    return hits;
}

// MSVC std::string 0x1C 字节：<15 SSO 就地；>=16 heap ptr @+0
// 单独在 heap 分配完整 std::string 对象；返回其地址（供 param+0x10 等作为 std::string* 使用）
function makeStdString(s){
    const obj = Memory.alloc(0x1C);
    for (let i = 0; i < 0x1C; i += 4) obj.add(i).writeU32(0);
    const n = s.length;
    if (n <= 15){
        const buf = new Uint8Array(16);
        for (let i = 0; i < n; i++) buf[i] = s.charCodeAt(i) & 0xff;
        obj.writeByteArray(buf.buffer);
        obj.add(0x10).writeU32(n);
        obj.add(0x14).writeU32(15);
    } else {
        const arr = new Uint8Array(n);
        for (let i = 0; i < n; i++) arr[i] = s.charCodeAt(i) & 0xff;
        const heap = Memory.alloc(n + 1);
        heap.writeByteArray(arr.buffer);
        heap.add(n).writeU8(0);
        obj.writeU32(heap.toUInt32());
        obj.add(0x10).writeU32(n);
        obj.add(0x14).writeU32(n);
    }
    return obj;
}

// CdnUploadParam 布局（type5 反汇编实证）：
//   +0x00 vtable
//   +0x10 std::string*  path        (type5: mov eax,[edx+0x10]; push eax; call fstat)
//   +0x14 std::string*  (md5?)
//   +0x18 std::string*  (conv/file_id?)
//   +0x1c uint32  file_type
// CdnUploadParam layout（type5 反汇编 + 试探实证）:
//   +0x00 vtable (0xb955b58 VA)
//   +0x04 …             (未确认，保持 0)
//   +0x10 char* file_path  ← type5: mov eax,[edx+0x10]; push eax
//   +0x14 uint32 path_len   ← 之前 char*+len 组合 called=True 不崩
//   +0x18 …
//   +0x1c uint32 file_type = 5
function initCdnUploadParam(p, pathStr, md5Str, convStr){
    for (let i = 0; i < CFG.param_size; i += 4) p.add(i).writeU32(0);
    p.writeU32(W0 + CFG.param_vtable);
    if (pathStr){
        const n = pathStr.length;
        const arr = new Uint8Array(n);
        for (let i = 0; i < n; i++) arr[i] = pathStr.charCodeAt(i) & 0xff;
        const heap = Memory.alloc(n + 1);
        heap.writeByteArray(arr.buffer);
        heap.add(n).writeU8(0);
        p.add(0x10).writeU32(heap.toUInt32());
        p.add(0x14).writeU32(n);
    }
    void md5Str; void convStr;
}

function defaultParamFromInit(){
    // InitFromDefault @ param_init: mov ecx,[ebp+8]; push <default>; call copy
    const init = WX.add(CFG.param_init);
    const bytes = new Uint8Array(init.readByteArray(24));
    for (let i = 0; i < bytes.length - 5; i++){
        if (bytes[i] !== 0x68) continue;
        const imm = bytes[i+1]|(bytes[i+2]<<8)|(bytes[i+3]<<16)|(bytes[i+4]<<24);
        return {va:'0x'+(imm>>>0).toString(16), rva:'0x'+((imm>>>0)-W0).toString(16), source:'init_push'};
    }
    return null;
}

function writeStdString(base, s){
    const n = s.length;
    const arr = new Uint8Array(n);
    for (let i = 0; i < n; i++) arr[i] = s.charCodeAt(i) & 0xff;
    if (n <= 15){
        const buf = new Uint8Array(16);
        for (let i = 0; i < n; i++) buf[i] = arr[i];
        base.writeByteArray(buf.buffer);
        base.add(0x10).writeU32(n);
        base.add(0x14).writeU32(15);
        return {kind:'sso', n:n};
    }
    const heap = Memory.alloc(n + 1);
    heap.writeByteArray(arr.buffer);
    heap.add(n).writeU8(0);
    base.writeU32(heap.toUInt32());
    base.add(0x10).writeU32(n);
    base.add(0x14).writeU32(n);
    return {kind:'heap', n:n, ptr:heap.toString()};
}

function dumpParam(label, p){
    const out = {label:label, va:p.toString(), dwords:[], strings:[]};
    for (let k = 0; k < CFG.param_size / 4; k++){
        out.dwords.push('0x'+u32(p.add(k*4)).toString(16));
    }
    for (let off = 0; off + 0x18 <= CFG.param_size; off += 4){
        try {
            const size = u32(p.add(off + 0x10));
            const cap = u32(p.add(off + 0x14));
            if (size === 0 || size > 512 || cap < size) continue;
            let dp = p.add(off);
            if (size > 15){
                const ptrVal = u32(p.add(off));
                if (ptrVal < 0x10000) continue;
                dp = ptr(ptrVal);
            }
            const bytes = new Uint8Array(dp.readByteArray(size));
            let s = '';
            for (let i = 0; i < size; i++){
                const b = bytes[i];
                s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
            }
            if (s.length >= 1) out.strings.push({off:'0x'+off.toString(16), s:s});
        } catch(e){}
    }
    return out;
}

function probeUpload(vtables){
    const byClass = {};
    let total = 0;
    const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
    for (let i = 0; i < vtables.length; i++){
        const pat = vtPat(vtables[i].rva);
        let n = 0;
        for (let ri = 0; ri < ranges.length; ri++){
            try { n += Memory.scanSync(ranges[ri].base, ranges[ri].size, pat).length; }
            catch(e){}
        }
        byClass[vtables[i].name] = n;
        total += n;
    }
    return {total:total, byClass:byClass};
}

function watchMs(ms, patchConv){
    const patterns = [];
    for (let i = 0; i < CFG.watch_vtables.length; i++){
        patterns.push({
            name: CFG.watch_vtables[i].name,
            bytes: vtPat(CFG.watch_vtables[i].rva)
        });
    }
    const priv = [];
    const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
    for (let i = 0; i < ranges.length; i++){
        if (ranges[i].file) continue;
        if (ranges[i].size < 0x1000 || ranges[i].size > 0x8000000) continue;
        priv.push(ranges[i]);
    }
    const seen = {};
    const dumps = [];
    const patches = [];
    const t0 = Date.now();
    while (Date.now() - t0 < ms){
        for (let p = 0; p < patterns.length; p++){
            const pat = patterns[p];
            for (let ri = 0; ri < priv.length; ri++){
                let ms2;
                try { ms2 = Memory.scanSync(priv[ri].base, priv[ri].size, pat.bytes); }
                catch(e){ continue; }
                for (let j = 0; j < ms2.length; j++){
                    const key = pat.name + '@' + ms2[j].address;
                    if (seen[key]) continue;
                    seen[key] = true;
                    dumps.push({class_name:pat.name, addr:ms2[j].address.toString()});
                    send({t:'cdn_task', class_name:pat.name, addr:ms2[j].address.toString()});
                }
            }
        }
        if (patchConv && CFG.post_send_rva){
            const postPat = vtPat(CFG.post_send_rva);
            for (let ri = 0; ri < priv.length; ri++){
                let ms2;
                try { ms2 = Memory.scanSync(priv[ri].base, priv[ri].size, postPat); }
                catch(e){ continue; }
                for (let j = 0; j < ms2.length; j++){
                    const task = ms2[j].address;
                    const pkgPtr = u32(task.add(0x30));
                    if (!pkgPtr || pkgPtr < 0x10000) continue;
                    const convBase = ptr(pkgPtr).add(0x28);
                    let size, cap, dataPtr;
                    try {
                        size = u32(convBase.add(0x10));
                        cap = u32(convBase.add(0x14));
                    } catch(e){ continue; }
                    if (size !== patchConv.length) continue;
                    dataPtr = size <= 15 ? convBase : ptr(u32(convBase));
                    const key = 'PostSend@'+task.toString();
                    if (seen[key]) continue;
                    seen[key] = true;
                    try {
                        const arr = new Uint8Array(patchConv.length);
                        for (let i = 0; i < patchConv.length; i++) arr[i] = patchConv.charCodeAt(i);
                        dataPtr.writeByteArray(arr.buffer);
                        patches.push({task:task.toString(), to:patchConv, ok:true});
                    } catch(e){
                        patches.push({task:task.toString(), err:e.message});
                    }
                }
            }
        }
    }
    return {n_tasks:dumps.length, dumps:dumps, patches:patches, duration_ms:Date.now()-t0};
}

rpc.exports = {
    invoke: function(cfgJson){
        const cfg = JSON.parse(cfgJson);
        const result = {ok:false, steps:[]};

        const fsHits = heapSingleton(CFG.fs_vtable);
        result.file_service_hits = fsHits;
        if (!fsHits.length){
            result.err = 'FileService singleton not found on heap';
            return result;
        }
        const thisVa = fsHits[0];
        result.this_va = thisVa;
        result.steps.push('FileService='+thisVa);

        const inner = u32(ptr(thisVa).add(0x10));
        const gate = u32(ptr(inner).add(0x48));
        result.inner_va = '0x'+inner.toString(16);
        result.inner_gate_48 = gate;
        if (!gate){
            result.err = 'FileService inner +0x48 is null (not logged in?)';
            return result;
        }

        result.default_param = defaultParamFromInit();

        const param = Memory.alloc(CFG.param_size + 16);
        Memory.protect(param, CFG.param_size + 16, 'rw-');

        result.steps.push('initCdnUploadParam (std::string* fields)');
        initCdnUploadParam(param, cfg.silk_path || '', cfg.md5 || '', cfg.conv_id || '');
        result.param_after_init = dumpParam('after_init', param);

        // file_type 最后写；md5/conv 等 offset 未完全验证，默认不 patch
        param.add(CFG.field_type).writeU32(cfg.file_type >>> 0);
        result.steps.push('file_type='+cfg.file_type+' @+0x'+CFG.field_type.toString(16));

        result.param_final = dumpParam('final', param);

        const cbDone = Memory.alloc(0x40);
        const cbProg = Memory.alloc(0x40);
        for (let i = 0; i < 0x40; i += 4){ cbDone.add(i).writeU32(0); cbProg.add(i).writeU32(0); }

        const fnVa = WX.add(CFG.upload_fn);
        result.fn_va = fnVa.toString();
        result.param_va = param.toString();
        result.cb_done = cbDone.toString();
        result.cb_prog = cbProg.toString();

        if (cfg.dry_run){
            result.ok = true;
            result.dry_run = true;
            result.steps.push('dry-run skip NativeFunction');
            return result;
        }

        const before = probeUpload(CFG.watch_vtables);
        result.probe_before = before;

        result.steps.push('CdnUploadFile NativeFunction');
        try {
            const upload = new NativeFunction(fnVa, 'void',
                ['pointer', 'pointer', 'pointer', 'pointer'], 'thiscall');
            upload(ptr(thisVa), param, cbDone, cbProg);
            result.called = true;
            result.ok = true;
        } catch(e){
            result.call_err = e.message;
            result.err = e.message;
            return result;
        }

        // 给异步 task 一点时间
        const watch = watchMs(cfg.watch_ms || 12000, cfg.patch_conv || '');
        result.watch = watch;
        result.probe_after = probeUpload(CFG.watch_vtables);
        return result;
    }
};
send({t:'ready'});
"""


def _attach(pid: int, cfg: dict):
    import frida
    js = FRIDA_JS.replace("__CFG__", json.dumps(cfg))
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
            elif p.get("t") == "cdn_task":
                print(f"  [cdn] {p['class_name']} @{p['addr']}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(50):
        if ready["v"]:
            break
        time.sleep(0.1)
    if not ready["v"]:
        raise RuntimeError("frida script not ready")
    return session, script


def _build_cfg() -> dict:
    return {
        "fs_vtable": M2C["FileService_vtable"],
        "upload_fn": M2C["CdnUploadFile_slot2"],
        "param_size": M2C["CdnUploadParam_size"],
        "param_vtable": M2C["CdnUploadParam_vtable"],
        "param_init": M2C["CdnUploadParam_init"],
        "field_type": M2C["CdnUploadParam_field_type"],
        "post_send_rva": POST_SEND_MESSAGE_TASK2,
        "watch_vtables": [{"name": n, "rva": r} for n, r in WATCH_VTABLES.items()],
    }


def cmd_invoke(args: argparse.Namespace) -> int:
    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe")
        return 1

    silk = None
    if args.silk or (OUT_DIR / "poc_staged_voice.json").is_file():
        class _A:
            pass
        a = _A()
        a.silk = args.silk or ""
        a.no_temp = True
        try:
            silk = _resolve_staged_silk(a)
        except FileNotFoundError as e:
            if args.silk:
                raise
            print(f"[!] {e}")
            return 1

    cfg_json = {
        "dry_run": args.dry_run,
        "silk_path": str(silk.silk_path) if silk else "",
        "filename": silk.filename if silk else "",
        "md5": silk.md5 if silk else "",
        "file_type": args.file_type,
        "conv_id": args.to_conv or "FILEASSIST",
        "patch_conv": args.to_conv or "",
        "watch_ms": args.watch * 1000,
    }

    print(f"[*] M2c invoke PID={pid} dry_run={args.dry_run}")
    if silk:
        print(f"    silk={silk.silk_path}")
        print(f"    md5={silk.md5}  size={silk.size}")
    print(f"    file_type={args.file_type}  conv={cfg_json['conv_id']}")

    session, script = _attach(pid, _build_cfg())
    t0 = time.monotonic()
    result = script.exports_sync.invoke(json.dumps(cfg_json))
    print(f"[+] done in {time.monotonic()-t0:.1f}s")
    try:
        script.unload()
        session.detach()
    except Exception:
        pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"m2c_invoke_{ts}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print("=" * 72)
    print(f"  FileService     = {result.get('this_va')}")
    print(f"  inner +0x48     = {result.get('inner_gate_48')}")
    print(f"  default_param   = {(result.get('default_param') or {}).get('rva')}")
    print(f"  called          = {result.get('called')}")
    if result.get("probe_before"):
        print(f"  upload before   = {result['probe_before'].get('byClass')}")
    if result.get("probe_after"):
        print(f"  upload after    = {result['probe_after'].get('byClass')}")
    if result.get("watch"):
        w = result["watch"]
        print(f"  watch tasks     = {w.get('n_tasks')}  patches={len(w.get('patches') or [])}")
    if result.get("err"):
        print(f"  ERROR           = {result['err']}")
    print("=" * 72)
    print(f"[+] → {out.name}")

    if result.get("param_final"):
        print("\n[param strings]")
        for s in result["param_final"].get("strings") or []:
            print(f"  {s['off']}: {s['s'][:100]}")

    if not result.get("ok"):
        return 1
    after = (result.get("probe_after") or {}).get("byClass") or {}
    upload_n = after.get("CdnUploadFileTask", 0)
    if result.get("called") and upload_n > 0:
        print("\n[+] M2c 成功信号：CdnUploadFileTask 堆上出现实例")
        return 0
    if result.get("dry_run"):
        return 0
    if result.get("called"):
        print("\n[i] 已调用未崩，但短窗内 CdnUploadFileTask 仍为 0；可能 param 字段不全或异步更慢")
        return 0
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if args.silk:
        staged = stage_silk(Path(args.silk), also_temp=not args.no_temp)
        meta = OUT_DIR / "poc_staged_voice.json"
        meta.write_text(json.dumps({
            "silk_path": str(staged.silk_path),
            "filename": staged.filename,
            "md5": staged.md5,
            "size": staged.size,
            "temp_path": str(staged.temp_path) if staged.temp_path else None,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] staged → {staged.silk_path}")
    return cmd_invoke(args)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="M2c: NativeFunction CdnUploadFile invoke")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--silk", default="")
    ap.add_argument("--to-conv", default="", help="目标 conv_id；非空则 watch 内 hijack PostSendMessageTask2")
    ap.add_argument("--file-type", type=int, default=M2C["FileType_voice"])
    ap.add_argument("--watch", type=int, default=12, help="调用后监视秒数")
    ap.add_argument("--dry-run", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    p_inv = sub.add_parser("invoke", help="调用 CdnUploadFile")
    p_inv.set_defaults(func=cmd_invoke)

    p_run = sub.add_parser("run", help="stage + invoke")
    p_run.add_argument("--no-temp", action="store_true")
    p_run.set_defaults(func=cmd_run)

    args = ap.parse_args(argv)
    if not args.cmd:
        args.cmd = "invoke"
        args.func = cmd_invoke
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
