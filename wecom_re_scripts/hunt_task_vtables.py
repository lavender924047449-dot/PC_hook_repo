# hunt_task_vtables.py — M1 补丁 · 找出语音/视频/文件走的"别的 Task 类"vtable
# =============================================================================
#
# 背景：M1 第一轮发现 voice/video/file 扫不到 PostSendMessageTask2 task。
# 假设它们走别的 Task 类。本脚本不限定 vtable，扫堆里**所有一个 dword 指向
# wxwork.exe .text 段的对象**，按 vtable 分组、diff 出"仅在 voice 期间活跃"
# 的 vtable 集合 = 语音相关 Task 类候选。
#
# 用法：每种 --type 跑一次（保持发消息动作），完了自动 dump JSON。
#      跑完多种类型后 diff_task_vtables.py 找类型特有 vtable。
#
# 严格约束：只读扫堆，不 hook。
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

MSG_TYPES = ("text", "image", "voice", "video", "file",
             "miniprogram", "sticker", "location", "card", "video_channel")


FRIDA_JS = r"""
'use strict';

const wx = Process.enumerateModules().filter(function(m){
    return m.name.toLowerCase() === 'wxwork.exe';
})[0];
if (!wx) throw new Error('wxwork.exe not loaded');
const WXBASE = wx.base.toUInt32();
const WXSIZE = wx.size;
const WXEND  = WXBASE + WXSIZE;
send({t:'info', msg:'wx base=0x'+WXBASE.toString(16)+' size=0x'+WXSIZE.toString(16)});

function u32(p){ try { return p.readU32(); } catch(e){ return 0; } }
function isReadable(p, len){
    try { p.readByteArray(len); return true; } catch(e){ return false; }
}

/* 抓一个 heap 范围里所有 dword-aligned 位置，
   如果 [addr] 指向 wxwork.exe 代码段 → 记录候选 vtable。
   为了避免爆量，只统计每个候选 vtable 的实例计数，不记具体地址。 */
rpc.exports = {
    scanOnce: function(){
        const counts = {};  // { vtable_va_hex : n_instances }
        const ranges = Process.enumerateRanges({protection:'rw-', coalesce:false});
        let scanned = 0;
        for (let i = 0; i < ranges.length; i++){
            const r = ranges[i];
            // 只关心私有堆（跳过 mapped file 之类）
            if (r.file) continue;
            const size = r.size;
            if (size < 0x100 || size > 0x8000000) continue;
            let buf;
            try { buf = new Uint32Array(r.base.readByteArray(size)); }
            catch(e){ continue; }
            scanned += size;
            for (let j = 0; j < buf.length; j++){
                const v = buf[j];
                if (v >= WXBASE && v < WXEND){
                    // 候选 vtable pointer
                    const k = '0x' + (v - WXBASE).toString(16);  // 存 RVA
                    counts[k] = (counts[k] || 0) + 1;
                }
            }
        }
        return {counts:counts, scanned_bytes:scanned};
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


def hunt_loop(pid: int, msg_type: str, duration: int, interval_ms: int) -> dict:
    print(f"[*] hunting vtables, msg_type={msg_type}, duration={duration}s, interval={interval_ms}ms")
    import frida
    session = frida.get_local_device().attach(pid)
    script = session.create_script(FRIDA_JS)
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

    # 每一次扫的结果都记下来 (samples[i] = {rva -> count}), 后面做时间线分析
    samples: list[dict] = []
    t_start = time.monotonic()
    deadline = t_start + duration
    last_print = t_start
    print(f"[*] 现在配合发一条 {msg_type} 消息给 FTA，脚本每 {interval_ms}ms 扫一次...")
    print(f"[i] 语音/视频/文件类：等脚本开始扫再触发发送动作")
    while time.monotonic() < deadline:
        try:
            r = script.exports_sync.scan_once()
        except Exception as e:
            print(f"[!] scan #{len(samples)} failed: {e}")
            break
        samples.append({
            "t": time.monotonic() - t_start,
            "counts": r["counts"],
            "scanned_bytes": r["scanned_bytes"],
        })
        # 5 秒打一次进度
        if time.monotonic() - last_print >= 5.0:
            n_uniq = len(samples[-1]["counts"])
            print(f"  [+{time.monotonic()-t_start:5.1f}s] "
                  f"scan #{len(samples)}, {n_uniq} unique vtables, "
                  f"{samples[-1]['scanned_bytes']/1024/1024:.0f}MB")
            last_print = time.monotonic()
        time.sleep(interval_ms / 1000.0)

    try:
        script.unload(); session.detach()
    except Exception:
        pass

    return {
        "msg_type": msg_type,
        "pid": pid,
        "duration_sec": time.monotonic() - t_start,
        "n_scans": len(samples),
        "samples": samples,
    }


def _summarize(result: dict) -> dict:
    """把 samples 合成：max_count / seen_in_n_scans 每个 vtable。"""
    all_rvas: dict[str, dict] = {}
    for s in result["samples"]:
        for rva, cnt in s["counts"].items():
            if rva not in all_rvas:
                all_rvas[rva] = {"max_count": 0, "seen_in": 0, "total_hits": 0}
            r = all_rvas[rva]
            r["max_count"] = max(r["max_count"], cnt)
            r["seen_in"] += 1
            r["total_hits"] += cnt
    return all_rvas


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="hunt wework Task vtables in wxwork heap")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--type", choices=MSG_TYPES, required=True)
    ap.add_argument("--duration", type=int, default=45)
    ap.add_argument("--interval-ms", type=int, default=100)
    args = ap.parse_args(argv)

    pid = args.pid or _find_wxwork_pid()
    if pid is None:
        print("[!] no WXWork.exe running")
        return 1
    print(f"[*] target PID={pid}")

    result = hunt_loop(pid, args.type, args.duration, args.interval_ms)

    # 内联 summarize，方便查看
    summary = _summarize(result)
    result["summary"] = summary

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = OUT_DIR / f"vtable_hunt_{args.type}_{ts}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                        encoding="utf-8")

    print()
    print("=" * 70)
    print(f"[+] {result['n_scans']} scans, {len(summary)} unique vtables observed")
    # 头 20 名（按 max_count）
    top = sorted(summary.items(), key=lambda x: -x[1]["max_count"])[:20]
    print(f"\n[+] Top 20 vtables by max instance count:")
    for rva, s in top:
        print(f"    RVA {rva:<10}  max={s['max_count']:<4}  seen_in={s['seen_in']:<4}"
              f"  total_hits={s['total_hits']}")

    print(f"\n[+] → {out_path.name}")
    print(f"[i] 跑完 voice/video/file 三种后，diff_task_vtables.py 找类型特有 vtable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
