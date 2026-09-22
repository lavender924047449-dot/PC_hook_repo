# poc_voice_cdn_inject.py — M2b · 无 UI 语音 CDN 注入 PoC
# =============================================================================
#
# B 路线核心：不依赖 PC「按住说话」，在企微 CDN 上传链路上注入素材库 .silk。
#
# 子命令：
#   stage    — 把素材库 silk 复制到 Cache/Voice/ 下（企微命名规范）
#   probe    — 空闲态扫堆，看 CDN Task 是否存在
#   watch    — 监视 CDN Task 出现并 dump（可选 --patch-path 覆写 silk 路径）
#   inject   — stage + watch 一条龙（校准阶段可配合手机触发一次上传以验证 patch）
#
# 路径覆写规则（与 NativeRouter conv_id 相同）：
#   * 只 writeByteArray，不改 size/cap/ptr
#   * 新路径字节长度必须与旧路径完全一致
#   * 脚本会自动把 staged 文件名 pad 到与 task 内路径等长
#
# 严格约束：禁止 Interceptor.attach / .replace
#
# 示例：
#   python runtime/wecom_re/poc_voice_cdn_inject.py stage --silk path/to/voice.silk
#   python runtime/wecom_re/poc_voice_cdn_inject.py probe
#   python runtime/wecom_re/poc_voice_cdn_inject.py watch --duration 60 --patch-path
#   python runtime/wecom_re/poc_voice_cdn_inject.py inject --silk voice.silk --to-conv S:xxx_yyy
# =============================================================================

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

BASE_DIR = Path(r"d:\Only internship outputs\Test-Voice")
OUT_DIR = BASE_DIR / "runtime" / "wecom_re"
WXWORK_ROOT = Path.home() / "Documents" / "WXWork"

from cdn_task_constants import (  # noqa: E402
    CDN_UPLOAD_VTABLES,
    WATCH_VTABLES,
    POST_SEND_MESSAGE_TASK2,
)

TASK_DUMP_BYTES = 0x600

FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base;
send({t:'info', msg:'wx base=' + WXBASE});

const TASK_DUMP = __TASK_DUMP__;

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }

function tryStdString(base){
    let ptrOrSso, size, cap;
    try {
        ptrOrSso = u32(base);
        size = u32(base.add(0x10));
        cap  = u32(base.add(0x14));
    } catch(e){ return null; }
    if (size > 0x10000 || cap > 0x400000 || cap < size) return null;
    if (size === 0) return {kind:'empty', size:0, cap:cap, str:'', str_obj: base.toString()};
    let dataPtr = base;
    if (size <= 15){
        dataPtr = base;
    } else {
        if (ptrOrSso < 0x10000) return null;
        dataPtr = ptr(ptrOrSso);
    }
    let bytes;
    try { bytes = new Uint8Array(dataPtr.readByteArray(size)); }
    catch(e){ return null; }
    let s = '';
    for (let i = 0; i < size; i++){
        const b = bytes[i];
        s += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
    }
    return {
        kind: size <= 15 ? 'sso' : 'heap',
        size: size, cap: cap,
        str: s,
        str_obj: base.toString(),
        data_ptr: dataPtr.toString(),
        heap_ptr: size <= 15 ? null : ('0x'+ptrOrSso.toString(16)),
    };
}

function scanStrings(base, len){
    const out = [];
    for (let off = 0; off + 0x18 <= len; off += 4){
        const s = tryStdString(base.add(off));
        if (s && s.size >= 1 && s.str.length >= 1) out.push({off:'0x'+off.toString(16), ...s});
    }
    return out;
}

function vtPattern(rva){
    const vtVA = WXBASE.add(rva).toUInt32();
    return [
        (vtVA & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 8) & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 16) & 0xff).toString(16).padStart(2, '0'),
        ((vtVA >>> 24) & 0xff).toString(16).padStart(2, '0')
    ].join(' ');
}

function fitPathLen(path, len){
    if (path.length === len) return path;
    if (path.length < len){
        const pad = len - path.length;
        const idx = path.lastIndexOf('.silk');
        if (idx < 0) return null;
        let padStr = '';
        for (let i = 0; i < pad; i++) padStr += '_';
        return path.slice(0, idx) + padStr + path.slice(idx);
    }
    const idx = path.lastIndexOf('\\');
    if (idx < 0) return null;
    const dir = path.slice(0, idx + 1);
    const file = path.slice(idx + 1);
    const dot = file.lastIndexOf('.silk');
    if (dot < 0) return null;
    const stem = file.slice(0, dot);
    const suffix = file.slice(dot);
    const avail = len - dir.length - suffix.length;
    if (avail < 8) return null;
    return dir + stem.slice(0, avail) + suffix;
}

function patchStringData(dataPtrHex, newStr){
    const p = ptr(dataPtrHex);
    if (newStr.length === 0) return {ok:false, err:'empty newStr'};
    try {
        const arr = new Uint8Array(newStr.length);
        for (let i = 0; i < newStr.length; i++) arr[i] = newStr.charCodeAt(i);
        p.writeByteArray(arr.buffer);
        const verify = new Uint8Array(p.readByteArray(newStr.length));
        let vs = '';
        for (let i = 0; i < verify.length; i++){
            const b = verify[i];
            vs += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '?';
        }
        return {ok: true, verify: vs};
    } catch(e){
        return {ok:false, err: e.message};
    }
}

/* 从 scan 命中点提取完整 Windows 路径（不要求 std::string 布局） */
function extractPathAround(hitAddr){
    let raw = '';
    let start = null;
    try {
        start = hitAddr.sub(160);
        const u = new Uint8Array(start.readByteArray(512));
        for (let i = 0; i < u.length; i++){
            const b = u[i];
            raw += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '\n';
        }
    } catch(e){ return null; }
    if (!start) return null;
    // 找含 Cache\Voice 且以 .silk 结尾的路径片段
    const lines = raw.split('\n');
    for (let i = 0; i < lines.length; i++){
        const line = lines[i];
        if (line.indexOf('Cache\\Voice') < 0 && line.indexOf('Cache/Voice') < 0) continue;
        if (line.indexOf('.silk') < 0) continue;
        // 从 line 里抠最长合法路径
        let best = '';
        for (let j = 0; j < line.length; j++){
            if (line[j] !== 'C' || j + 1 >= line.length || line[j+1] !== ':') continue;
            let k = j;
            while (k < line.length){
                const c = line.charCodeAt(k);
                if (c >= 0x20 && c <= 0x7e) k++; else break;
            }
            const cand = line.slice(j, k);
            if (cand.indexOf('.silk') >= 0 && cand.length > best.length) best = cand;
        }
        if (best.length >= 20) {
            // 计算路径在内存中的起始地址
            const idx = raw.indexOf(best);
            if (idx >= 0){
                return {
                    str: best,
                    size: best.length,
                    data_ptr: start.add(idx).toString(),
                };
            }
        }
    }
    return null;
}

function dumpCdnTask(taskAddr, className, vtableRva){
    const strings = scanStrings(taskAddr, TASK_DUMP);
    const silkHits = [];
    for (let i = 0; i < strings.length; i++){
        const s = strings[i];
        if (s.str.indexOf('.silk') >= 0 || s.str.indexOf('Cache\\Voice') >= 0 ||
            s.str.indexOf('Cache/Voice') >= 0) silkHits.push(s);
    }
    return {
        task_addr: taskAddr.toString(),
        class_name: className,
        vtable_rva: '0x'+vtableRva.toString(16),
        strings: strings,
        silk_hits: silkHits,
    };
}

rpc.exports = {
    watchAndPatch: function(cfgJson){
        const cfg = JSON.parse(cfgJson);
        const vtables = cfg.vtables;  // [{name,rva},...]
        const patchPath = cfg.patch_path || '';
        const patchConv = cfg.patch_conv || '';
        const postSendRva = cfg.post_send_rva || 0;
        const dryRun = !!cfg.dry_run;

        const patterns = [];
        for (let i = 0; i < vtables.length; i++){
            patterns.push({name:vtables[i].name, rva:vtables[i].rva,
                           bytes: vtPattern(vtables[i].rva)});
        }
        let postPat = null;
        if (postSendRva) postPat = vtPattern(postSendRva);

        // 只扫私有堆，跳过 mapped file，提速 ~2x
        const allRanges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        const ranges = [];
        for (let ri = 0; ri < allRanges.length; ri++){
            if (allRanges[ri].file) continue;
            if (allRanges[ri].size < 0x1000 || allRanges[ri].size > 0x8000000) continue;
            ranges.push(allRanges[ri]);
        }
        send({t:'info', msg:'heap ranges (private rw-)=' + ranges.length});

        const seen = {};
        const patches = [];
        const dumps = [];
        const pathHits = [];
        let scans = 0;
        const t0 = Date.now();
        const deadline = t0 + cfg.duration_ms;
        const pathNeedle = cfg.path_needle || 'Cache\\Voice';

        while (Date.now() < deadline){
            scans++;
            for (let p = 0; p < patterns.length; p++){
                const pat = patterns[p];
                for (let ri = 0; ri < ranges.length; ri++){
                    const r = ranges[ri];
                    let ms;
                    try { ms = Memory.scanSync(r.base, r.size, pat.bytes); }
                    catch(e){ continue; }
                    for (let j = 0; j < ms.length; j++){
                        const addr = ms[j].address;
                        const key = pat.name + '@' + addr.toString();
                        if (seen[key]) continue;
                        seen[key] = true;
                        const rec = dumpCdnTask(addr, pat.name, pat.rva);
                        dumps.push(rec);
                        send({t:'cdn_task', class_name: pat.name, addr: addr.toString(),
                              n_silk: rec.silk_hits.length});

                        if (patchPath && rec.silk_hits.length){
                            for (let si = 0; si < rec.silk_hits.length; si++){
                                const hit = rec.silk_hits[si];
                                const fitted = fitPathLen(patchPath, hit.size);
                                if (!fitted || fitted.length !== hit.size) continue;
                                if (dryRun){
                                    patches.push({type:'path', dry:true,
                                        task: addr.toString(), off: hit.off,
                                        from: hit.str, to: fitted});
                                } else {
                                    const pr = patchStringData(hit.data_ptr, fitted);
                                    patches.push({type:'path', dry:false,
                                        task: addr.toString(), off: hit.off,
                                        from: hit.str, to: fitted, result: pr});
                                }
                            }
                        }
                    }
                }
            }

            // 旁路：每 3 轮扫 Voice 路径（原始 C 串，不依赖 std::string 布局）
            if (patchPath && (scans === 1 || scans % 3 === 0)){
                let pat = '';
                for (let i = 0; i < pathNeedle.length; i++){
                    pat += (i ? ' ' : '') + pathNeedle.charCodeAt(i).toString(16).padStart(2,'0');
                }
                const pathRanges = Process.enumerateRanges({protection:'rw-', coalesce:false});
                for (let ri = 0; ri < pathRanges.length; ri++){
                    const r = pathRanges[ri];
                    let ms;
                    try { ms = Memory.scanSync(r.base, r.size, pat); }
                    catch(e){ continue; }
                    for (let j = 0; j < ms.length; j++){
                        const hitAddr = ms[j].address;
                        const p = extractPathAround(hitAddr);
                        if (!p) continue;
                        const key = 'path@' + p.str;
                        if (seen[key]) continue;
                        seen[key] = true;
                        pathHits.push(p);
                        send({t:'path_hit', str: p.str.slice(0, 100), size: p.size});
                        const fitted = fitPathLen(patchPath, p.size);
                        if (fitted && fitted.length === p.size){
                            if (dryRun){
                                patches.push({type:'path_raw', dry:true,
                                    data_ptr: p.data_ptr, from: p.str, to: fitted});
                            } else {
                                const pr = patchStringData(p.data_ptr, fitted);
                                patches.push({type:'path_raw', dry:false,
                                    data_ptr: p.data_ptr, from: p.str, to: fitted, result: pr});
                            }
                        }
                    }
                }
            }

            // 备用：PostSendMessageTask2 conv hijack
            if (patchConv && postPat){
                for (let ri = 0; ri < ranges.length; ri++){
                    const r = ranges[ri];
                    let ms;
                    try { ms = Memory.scanSync(r.base, r.size, postPat); }
                    catch(e){ continue; }
                    for (let j = 0; j < ms.length; j++){
                        const taskAddr = ms[j].address;
                        const pkgPtr = u32(taskAddr.add(0x30));
                        if (!pkgPtr || pkgPtr < 0x10000) continue;
                        const convBase = ptr(pkgPtr).add(0x28);
                        const conv = tryStdString(convBase);
                        if (!conv || conv.size !== patchConv.length) continue;
                        const key = 'PostSend@'+taskAddr.toString();
                        if (seen[key]) continue;
                        seen[key] = true;
                        if (dryRun){
                            patches.push({type:'conv', dry:true, task: taskAddr.toString(),
                                from: conv.str, to: patchConv});
                        } else {
                            const pr = patchStringData(conv.data_ptr, patchConv);
                            patches.push({type:'conv', dry:false, task: taskAddr.toString(),
                                from: conv.str, to: patchConv, result: pr});
                        }
                    }
                }
            }
        }

        return {scans, duration_ms: Date.now()-t0, dumps, patches,
                path_hits: pathHits, n_tasks: dumps.length, n_path_hits: pathHits.length};
    },

    probeOnce: function(vtablesJson){
        const vtables = JSON.parse(vtablesJson);
        const patterns = [];
        for (let i = 0; i < vtables.length; i++){
            patterns.push({name:vtables[i].name, rva:vtables[i].rva,
                           bytes: vtPattern(vtables[i].rva)});
        }
        const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        let total = 0;
        const byClass = {};
        for (let p = 0; p < patterns.length; p++){
            const pat = patterns[p];
            let n = 0;
            for (let ri = 0; ri < ranges.length; ri++){
                const r = ranges[ri];
                try { n += Memory.scanSync(r.base, r.size, pat.bytes).length; }
                catch(e){}
            }
            byClass[pat.name] = n;
            total += n;
        }
        return {total, byClass};
    }
};
send({t:'ready'});
"""


@dataclass
class StagedVoice:
    silk_path: Path
    filename: str
    month_dir: Path
    temp_path: Optional[Path]
    md5: str
    size: int


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


def _find_account_dir() -> Path:
    if not WXWORK_ROOT.is_dir():
        raise FileNotFoundError(f"WXWork root not found: {WXWORK_ROOT}")
    best: tuple[int, Path] | None = None
    for sub in WXWORK_ROOT.iterdir():
        if not sub.is_dir() or not sub.name.isdigit():
            continue
        voice = sub / "Cache" / "Voice"
        if voice.is_dir():
            n = sum(1 for _ in voice.rglob("*.silk"))
            if best is None or n > best[0]:
                best = (n, sub)
    if best is None:
        raise FileNotFoundError("no WXWork account with Cache/Voice found")
    return best[1]


def _wecom_voice_filename(now: datetime | None = None) -> str:
    """企微 silk 命名：2026_09_13_18_56_51_226.silk"""
    dt = now or datetime.now()
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y_%m_%d_%H_%M_%S_{ms:03d}.silk")


def _month_folder(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y-%m")


def _hint_silk_paths() -> str:
    lines = ["可用 .silk 示例（请替换 --silk 参数）："]
    meta = OUT_DIR / "poc_staged_voice.json"
    if meta.is_file():
        try:
            p = json.loads(meta.read_text(encoding="utf-8")).get("silk_path", "")
            if p:
                lines.append(f"  {p}  ← 上次 stage 产物，或直接用 watch --patch-path")
        except Exception:
            pass
    try:
        account = _find_account_dir()
        voice_dir = account / "Cache" / "Voice"
        found = sorted(voice_dir.rglob("*.silk"), key=lambda p: p.stat().st_mtime, reverse=True)
        for p in found[:3]:
            lines.append(f"  {p}")
    except Exception:
        pass
    return "\n".join(lines)


def stage_silk(
    source: Path,
    *,
    also_temp: bool = True,
    target_filename: str | None = None,
) -> StagedVoice:
    if not source.is_file():
        raise FileNotFoundError(
            f"silk not found: {source}\n"
            f"（「你的素材.silk」是文档占位符，不是真实路径）\n"
            f"{_hint_silk_paths()}"
        )

    account = _find_account_dir()
    now = datetime.now()
    filename = target_filename or _wecom_voice_filename(now)
    if not filename.endswith(".silk"):
        filename += ".silk"

    month_dir = account / "Cache" / "Voice" / _month_folder(now)
    month_dir.mkdir(parents=True, exist_ok=True)
    dest = month_dir / filename
    shutil.copy2(source, dest)

    temp_path: Path | None = None
    if also_temp:
        temp_dir = account / "Cache" / "Voice" / "Temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_path = temp_dir / str(uuid.uuid4())
        shutil.copy2(source, temp_path)

    data = dest.read_bytes()
    md5 = hashlib.md5(data).hexdigest()
    return StagedVoice(
        silk_path=dest,
        filename=filename,
        month_dir=month_dir,
        temp_path=temp_path,
        md5=md5,
        size=len(data),
    )


def _fit_path_length(full_path: str, required_len: int) -> str | None:
    """把路径 pad/trim 到 required_len（仅改文件名部分）。"""
    if len(full_path) == required_len:
        return full_path
    if len(full_path) < required_len:
        # 在文件名 stem 末尾 pad '_'
        pad = required_len - len(full_path)
        p = Path(full_path)
        stem = p.stem + ("_" * pad)
        return str(p.with_name(stem + p.suffix))
    # 过长：截断文件名（保留 .silk）
    p = Path(full_path)
    suffix = p.suffix
    base = str(p.parent) + "\\"
    avail = required_len - len(base) - len(suffix)
    if avail < 8:
        return None
    return base + p.stem[:avail] + suffix


def _voice_silk_snapshot(voice_root: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    if not voice_root.is_dir():
        return out
    for p in voice_root.rglob("*.silk"):
        try:
            out[str(p)] = p.stat().st_mtime
        except OSError:
            pass
    return out


def _diagnose_watch(
    result: dict,
    new_files: list[str],
    *,
    had_upload_signal: bool,
) -> None:
    n_task = result.get("n_tasks", 0)
    n_path = result.get("n_path_hits", 0)
    n_patch = len(result.get("patches") or [])
    scans = result.get("scans", 0)
    dur = (result.get("duration_ms") or 0) / 1000.0
    print()
    print("─" * 70)
    print("[诊断]")
    print(f"  扫堆 {scans} 次 / {dur:.1f}s  (~{scans/max(dur,0.1):.1f} 次/s)")
    print(f"  CDN Task 命中: {n_task}   路径字符串命中: {n_path}   patch: {n_patch}")
    if new_files:
        print(f"  Voice 缓存新文件: {len(new_files)} 个（PC 侧有语音落盘）")
        for f in new_files[:3]:
            print(f"    + {f}")
    else:
        print("  Voice 缓存新文件: 0  ← 60s 内 PC 未出现新 .silk")
    print()
    if n_task == 0 and n_path == 0 and not new_files:
        print("  结论: 窗口内**未触发 PC 端语音上传/落盘**。")
        print("  请重跑，看到「wx base=…」后**立即**用手机给 FTA 发一条语音。")
        print("  （仅手机 CDN 上传、PC 只同步的话，PC 堆上可能没有 CdnUploadFileTask）")
    elif new_files and n_task == 0:
        print("  结论: PC 收到新 silk（同步/下载完成），但 CdnUploadFileTask=0。")
        print("  → 手机发语音时，CDN **上传在手机**；PC 只做 **Download**，不会走 Upload Task。")
        print("  → 这不能校准「PC 无 UI 发出语音」；下一步需逆 FileService::CdnUploadFile。")
        if n_path == 0:
            print("  → path_hits=0 可能是路径扫描 bug；已修复 raw 路径提取，请再跑一次 watch。")
        else:
            print(f"  → 旁路扫到 {n_path} 条路径（多为历史缓存路径，不代表 upload 窗口）。")
    elif n_patch > 0:
        print("  结论: patch 已执行，请在企微确认 FTA/目标会话是否出现预期语音。")
    print("─" * 70)


def _attach_frida(pid: int):
    import frida
    js = FRIDA_JS.replace("__TASK_DUMP__", str(TASK_DUMP_BYTES))
    session = frida.get_local_device().attach(pid)
    script = session.create_script(js)
    ready = {"v": False}
    events: list[dict] = []

    def on_message(msg, _data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready":
                ready["v"] = True
            elif p.get("t") == "info":
                print(f"    [js] {p['msg']}")
            elif p.get("t") == "cdn_task":
                events.append(p)
                print(f"  [cdn] {p['class_name']} @{p['addr']} silk_hits={p['n_silk']}")
            elif p.get("t") == "path_hit":
                print(f"  [path] size={p.get('size')} {p.get('str', '')[:90]}")
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")

    script.on("message", on_message)
    script.load()
    for _ in range(30):
        if ready["v"]:
            break
        time.sleep(0.1)
    return session, script, events


def cmd_stage(args: argparse.Namespace) -> int:
    staged = stage_silk(Path(args.silk), also_temp=not args.no_temp)
    print(f"[+] staged silk → {staged.silk_path}")
    print(f"    filename = {staged.filename}")
    print(f"    size     = {staged.size} B")
    print(f"    md5      = {staged.md5}")
    if staged.temp_path:
        print(f"    temp     = {staged.temp_path}")
    meta = OUT_DIR / "poc_staged_voice.json"
    meta.write_text(json.dumps({
        "silk_path": str(staged.silk_path),
        "filename": staged.filename,
        "md5": staged.md5,
        "size": staged.size,
        "temp_path": str(staged.temp_path) if staged.temp_path else None,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] meta → {meta.name}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe")
        return 1
    print(f"[*] probe PID={pid}")
    session, script, _ = _attach_frida(pid)
    vtables = [{"name": n, "rva": rva} for n, rva in WATCH_VTABLES.items()]
    r = script.exports_sync.probe_once(json.dumps(vtables))
    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    print(f"[+] CDN Task instances on heap: total={r['total']}")
    for k, v in (r.get("byClass") or {}).items():
        print(f"    {k}: {v}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe")
        return 1

    patch_path_str = ""
    if args.patch_path:
        meta_path = OUT_DIR / "poc_staged_voice.json"
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            patch_path_str = meta["silk_path"]
        elif args.silk:
            staged = stage_silk(Path(args.silk), also_temp=False)
            patch_path_str = str(staged.silk_path)
        else:
            print("[!] --patch-path 需要先有 poc_staged_voice.json 或 --silk")
            return 1
        print(f"[*] will patch silk path → {patch_path_str}")

    print(f"[*] watch PID={pid} duration={args.duration}s dry_run={args.dry_run}")
    if not args.patch_path:
        print("[i] 纯 dump 模式：触发任意 CDN 上传（校准可用手机→FTA）")
    else:
        print("[i] patch 模式：task 内路径长度须与 staged 路径一致（脚本会自动 fit）")

    voice_root = _find_account_dir() / "Cache" / "Voice"
    snap_before = _voice_silk_snapshot(voice_root)

    print()
    print("=" * 70)
    print(">>> 倒计时开始：请立即用手机企微给 FTA 发一条语音（15 秒内） <<<")
    print("=" * 70)
    print()

    session, script, _ = _attach_frida(pid)
    cfg = {
        "vtables": [{"name": n, "rva": rva} for n, rva in WATCH_VTABLES.items()],
        "patch_path": "",
        "patch_conv": args.to_conv or "",
        "post_send_rva": POST_SEND_MESSAGE_TASK2 if args.to_conv else 0,
        "dry_run": args.dry_run,
        "duration_ms": args.duration * 1000,
        "path_needle": "Cache\\Voice",
    }

    # 若已知 patch 路径，先写入；watch 内按 hit.size 过滤
    if patch_path_str:
        cfg["patch_path"] = patch_path_str

    result = script.exports_sync.watch_and_patch(json.dumps(cfg))
    try:
        script.unload()
        session.detach()
    except Exception:
        pass

    snap_after = _voice_silk_snapshot(voice_root)
    new_files = [p for p in snap_after if p not in snap_before or snap_after[p] > snap_before.get(p, 0)]

    patches = result.get("patches") or []
    dumps = result.get("dumps") or []
    result["voice_new_files"] = new_files
    print()
    print("=" * 70)
    print(f"[+] scans={result.get('scans')} tasks={len(dumps)} "
          f"path_hits={result.get('n_path_hits', 0)} patches={len(patches)}")
    for p in patches:
        ok = p.get("result", {}).get("ok") if p.get("result") else p.get("dry")
        print(f"  [{p.get('type')}] {'DRY' if p.get('dry') else ('OK' if ok else 'FAIL')} "
              f"task={p.get('task')}")
        print(f"       {p.get('from', '')[:80]}")
        print(f"    →  {p.get('to', '')[:80]}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = OUT_DIR / f"poc_watch_{ts}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] → {out.name}")
    _diagnose_watch(result, new_files, had_upload_signal=bool(new_files))
    return 0 if (dumps or new_files or result.get("n_path_hits")) else 1


def _resolve_staged_silk(args: argparse.Namespace) -> StagedVoice:
    if args.silk:
        return stage_silk(Path(args.silk), also_temp=not args.no_temp)
    meta_path = OUT_DIR / "poc_staged_voice.json"
    if not meta_path.is_file():
        raise FileNotFoundError(
            "未指定 --silk，且 poc_staged_voice.json 不存在。\n"
            f"{_hint_silk_paths()}"
        )
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    p = Path(meta["silk_path"])
    if not p.is_file():
        raise FileNotFoundError(f"已 stage 的文件不存在: {p}\n请重新 stage --silk ...")
    return StagedVoice(
        silk_path=p,
        filename=meta.get("filename", p.name),
        month_dir=p.parent,
        temp_path=Path(meta["temp_path"]) if meta.get("temp_path") else None,
        md5=meta.get("md5", ""),
        size=meta.get("size", p.stat().st_size),
    )


def cmd_inject(args: argparse.Namespace) -> int:
    """stage + watch：B 路线 PoC 主入口。"""
    staged = _resolve_staged_silk(args)
    print(f"[+] using silk → {staged.silk_path}  md5={staged.md5}")

    args.patch_path = True
    args.silk = str(staged.silk_path)
    args.dry_run = args.dry_run
    if not args.to_conv:
        print("[i] 未指定 --to-conv：仅 dump/patch silk 路径，不改 conv_id")
    print()
    print("[*] 下一步：企微须有一条 CDN 上传链路被触发。")
    print("[*] 长期目标：FileService::CdnUploadFile 无 UI 调用（layout dump 完成后逆向）")
    print("[*] 当前 PoC：watch 窗口内若出现 CdnUploadFileTask，覆写其 silk 路径")
    print()
    return cmd_watch(args)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PoC: no-UI voice CDN inject")
    ap.add_argument("--pid", type=int, default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_stage = sub.add_parser("stage", help="copy silk into Cache/Voice/")
    p_stage.add_argument("--silk", required=True, help="source .silk file")
    p_stage.add_argument("--no-temp", action="store_true", help="skip Temp/ uuid copy")
    p_stage.set_defaults(func=cmd_stage)

    p_probe = sub.add_parser("probe", help="idle heap scan for CDN tasks")
    p_probe.set_defaults(func=cmd_probe)

    p_watch = sub.add_parser("watch", help="watch CDN tasks, optional patch")
    p_watch.add_argument("--duration", type=int, default=60)
    p_watch.add_argument("--patch-path", action="store_true",
                         help="patch .silk path in task when length matches")
    p_watch.add_argument("--silk", default="", help="source silk if not staged yet")
    p_watch.add_argument("--to-conv", default="", help="optional conv_id hijack target")
    p_watch.add_argument("--dry-run", action="store_true")
    p_watch.set_defaults(func=cmd_watch)

    p_inject = sub.add_parser("inject", help="stage + watch (main PoC)")
    p_inject.add_argument("--silk", default="",
                          help="source .silk；省略则复用 poc_staged_voice.json")
    p_inject.add_argument("--duration", type=int, default=60)
    p_inject.add_argument("--to-conv", default="")
    p_inject.add_argument("--dry-run", action="store_true")
    p_inject.add_argument("--no-temp", action="store_true")
    p_inject.set_defaults(func=cmd_inject)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
