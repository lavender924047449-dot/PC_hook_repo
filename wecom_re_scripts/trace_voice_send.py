# trace_voice_send.py — M2 起步 · 语音发送路径追踪（文件 + 内存字符串）
# =============================================================================
#
# 背景：PostSendMessageTask2 / HandleMessageResourcesTask / HandleForwardResourcesTask2
# 在 voice 发送期间堆上 0 命中 → 改走旁路：
#   1) 监视 %USERPROFILE%/Documents/WXWork/<uin>/Cache/Voice 新 .silk 文件
#   2) Frida 只读扫堆，找新出现的 ".silk" / "Cache\\Voice" / "Voice\\" 路径字符串
#
# 用法：
#   python runtime/wecom_re/trace_voice_send.py --duration 60
#   提示后给 FTA 按住说话 15-20 秒
#
# 严格约束：只读 attach，不 hook。
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
WXWORK_ROOT = Path.home() / "Documents" / "WXWork"

FRIDA_JS = r"""
'use strict';

const KEYWORDS = ['.silk', 'Cache\\Voice', 'Cache/Voice', 'Voice\\', 'Voice/', 'amr', 'SILK'];

function safeCstr(p, cap){ try { return p.readCString(cap || 512); } catch(e){ return null; } }

function scanStringsOnce(){
    const found = [];
    const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
    for (let ki = 0; ki < KEYWORDS.length; ki++){
        const kw = KEYWORDS[ki];
        let pat = '';
        for (let i = 0; i < kw.length; i++){
            const b = kw.charCodeAt(i).toString(16).padStart(2, '0');
            pat += (i ? ' ' : '') + b;
        }
        for (let ri = 0; ri < ranges.length; ri++){
            const r = ranges[ri];
            let hits;
            try { hits = Memory.scanSync(r.base, r.size, pat); }
            catch(e){ continue; }
            for (let hi = 0; hi < hits.length; hi++){
                const addr = hits[hi].address;
                // 尝试从命中点前 128 字节读完整路径
                let ctx = '';
                try {
                    const start = addr.sub(128);
                    ctx = safeCstr(start, 384) || '';
                } catch(e){}
                if (!ctx) ctx = safeCstr(addr, 256) || '';
                if (ctx.length < 4) continue;
                found.push({kw: kw, hit: addr.toString(), ctx: ctx.slice(0, 240)});
            }
        }
    }
    return found;
}

rpc.exports = {
    scanLoop: function(durationMs){
        const seen = {};
        const events = [];
        let scans = 0;
        const t0 = Date.now();
        while (Date.now() - t0 < durationMs){
            scans++;
            const hits = scanStringsOnce();
            for (let i = 0; i < hits.length; i++){
                const h = hits[i];
                const key = h.hit + '|' + h.kw;
                if (seen[key]) continue;
                seen[key] = h;
                events.push({t_ms: Date.now()-t0, scan: scans, ...h});
            }
        }
        return {scans, duration_ms: Date.now()-t0, events, all: Object.values(seen)};
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


def _find_voice_cache_dir() -> Path | None:
    if not WXWORK_ROOT.is_dir():
        return None
    best: tuple[int, Path] | None = None
    for sub in WXWORK_ROOT.iterdir():
        if not sub.is_dir() or not sub.name.isdigit():
            continue
        voice = sub / "Cache" / "Voice"
        if voice.is_dir():
            n = sum(1 for _ in voice.rglob("*") if _.is_file())
            if best is None or n > best[0]:
                best = (n, voice)
    return best[1] if best else None


def _snapshot_dir(d: Path) -> dict[str, tuple[int, float]]:
    out: dict[str, tuple[int, float]] = {}
    if not d.is_dir():
        return out
    for p in d.rglob("*"):
        if p.is_file():
            try:
                st = p.stat()
                out[str(p)] = (st.st_size, st.st_mtime)
            except OSError:
                pass
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--duration", type=int, default=60)
    args = ap.parse_args(argv)

    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe"); return 1
    voice_dir = _find_voice_cache_dir()
    print(f"[*] PID={pid}")
    print(f"[*] Voice cache: {voice_dir or '(not found)'}")

    before = _snapshot_dir(voice_dir) if voice_dir else {}
    print(f"[*] baseline: {len(before)} files in Voice cache")

    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
    ready = {"v": False}
    def on_msg(msg, _d):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "ready": ready["v"] = True
        elif msg.get("type") == "error":
            print(f"    [!] {msg.get('description')}")
    script.on("message", on_msg)
    script.load()
    for _ in range(30):
        if ready["v"]: break
        time.sleep(0.1)

    print(f"[*] 现在给 FTA 按住说话 15-20 秒...")
    t0 = time.monotonic()
    mem = script.exports_sync.scan_loop(args.duration * 1000)
    try: script.unload(); session.detach()
    except Exception: pass

    after = _snapshot_dir(voice_dir) if voice_dir else {}
    new_files = []
    for path, (sz, mt) in after.items():
        if path not in before:
            new_files.append({"path": path, "size": sz, "mtime": mt})
        elif before[path][0] != sz or before[path][1] != mt:
            new_files.append({"path": path, "size": sz, "mtime": mt, "changed": True})

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = {
        "pid": pid,
        "voice_cache_dir": str(voice_dir) if voice_dir else None,
        "duration_sec": time.monotonic() - t0,
        "new_voice_files": new_files,
        "memory_scans": mem.get("scans"),
        "memory_events": mem.get("events") or [],
        "memory_unique": mem.get("all") or [],
    }
    out_path = OUT_DIR / f"trace_voice_{ts}.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print("=" * 70)
    print(f"[+] 新/变更 Voice 缓存文件: {len(new_files)}")
    for f in new_files[:10]:
        print(f"    {f['size']:>8} B  {f['path']}")
    print(f"[+] 内存新字符串命中: {len(mem.get('events') or [])} events, "
          f"{len(mem.get('all') or [])} unique")
    for ev in (mem.get("events") or [])[:15]:
        ctx = (ev.get("ctx") or "").replace("\n", " ")[:80]
        print(f"    [+{ev.get('t_ms',0)/1000:5.1f}s] kw={ev.get('kw')} ctx={ctx!r}")
    print(f"\n[+] → {out_path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
