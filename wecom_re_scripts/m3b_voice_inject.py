# m3b_voice_inject.py — M3b-A：录音文件替换注入
#
# 原理：
#   企微 PC 录音 → 写入 Cache\Voice\Temp\*.silk → 录音结束 → move 到 Voice\YYYY-MM\
#   本脚本 watchdog 监视 Temp 目录，一旦出现新 .silk，立即用目标 silk 覆写。
#   用户只需：按住录音键 ≥1s → 松开 → 企微发出的就是目标 silk（合法 voice 上传）
#
# 用法：
#   python m3b_voice_inject.py --source poc_staged_voice.json [--once]
#   然后在企微里按录音键录 ≥1s 再松开

from __future__ import annotations
import argparse, json, shutil, sys, time
from datetime import datetime
from pathlib import Path
import threading

sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

OUT_DIR  = Path(__file__).resolve().parent
TEMP_DIR = Path(r"C:\Users\LENOVO\Documents\WXWork\1688855042791155\Cache\Voice\Temp")

def load_staged(src: str) -> dict:
    p = OUT_DIR / src if not Path(src).is_absolute() else Path(src)
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


def test_overwrite_lock(path: Path) -> bool:
    """测试 path 是否可被覆写（非独占锁）。"""
    try:
        with open(path, "r+b") as f:
            f.read(1)
        return True
    except PermissionError:
        return False
    except FileNotFoundError:
        return False


def inject_once(staged: dict, dry_run: bool = False) -> dict:
    """
    阻塞等待 Temp 目录出现新 .silk，然后用 staged silk 覆写。
    返回事件记录 dict。
    """
    source_path = Path(staged.get("silk_path", ""))
    if not source_path.is_file():
        print(f"[!] staged silk 不存在: {source_path}")
        return {"ok": False, "reason": "staged silk missing"}

    print(f"[*] 目标 silk: {source_path.name}  ({source_path.stat().st_size} B)")
    print(f"[*] 监视目录: {TEMP_DIR}")
    print(f"[*] 模式: {'DRY-RUN（只报告，不覆写）' if dry_run else '覆写注入'}")
    print()
    print("=" * 60)
    print("  操作：在企微里【按住录音键】录音 ≥1s，然后松开发送")
    print("=" * 60)

    # 记录监视开始时的已有文件
    known = set(TEMP_DIR.glob("*.silk")) if TEMP_DIR.is_dir() else set()

    t0 = time.monotonic()
    rec = {"ok": False, "source": str(source_path), "dry_run": dry_run}

    while time.monotonic() - t0 < 120:
        if not TEMP_DIR.is_dir():
            time.sleep(0.2)
            continue

        current = set(TEMP_DIR.glob("*.silk"))
        new_files = current - known

        for f in new_files:
            elapsed = time.monotonic() - t0
            print(f"  [+] 新 silk 出现: {f.name}  (+{elapsed:.2f}s)")
            rec["temp_silk"] = str(f)
            rec["detected_at"] = elapsed

            # 检测文件锁
            locked = not test_overwrite_lock(f)
            rec["locked"] = locked
            if locked:
                print(f"  [!] 文件被独占锁定，等待解锁...")
                # 最多等 3s
                for _ in range(30):
                    time.sleep(0.1)
                    if test_overwrite_lock(f):
                        locked = False
                        break
                rec["locked_after_wait"] = locked

            if locked:
                print(f"  [!] 等待超时，文件仍被锁定 — M3b-A 不可行（需走 M3b-B/C）")
                rec["ok"] = False
                rec["reason"] = "file_locked"
                return rec

            src_size = source_path.stat().st_size
            dst_size = f.stat().st_size if f.is_file() else 0
            rec["recorded_size"] = dst_size
            rec["target_size"] = src_size

            print(f"  [*] 已录制 silk: {dst_size} B  →  覆写为目标 silk: {src_size} B")

            if not dry_run:
                try:
                    shutil.copy2(source_path, f)
                    # 验证
                    actual = f.read_bytes()[:8]
                    expected = source_path.read_bytes()[:8]
                    if actual == expected:
                        print(f"  [✓] 覆写成功！等待企微发送...")
                        rec["ok"] = True
                        rec["injected"] = True
                    else:
                        print(f"  [!] 覆写后内容不符（可能被覆盖回去）")
                        rec["ok"] = False
                        rec["reason"] = "content_mismatch_after_copy"
                except Exception as e:
                    print(f"  [!] 覆写失败: {e}")
                    rec["ok"] = False
                    rec["reason"] = str(e)
            else:
                print(f"  [DRY-RUN] 不覆写，继续观察 5s...")
                time.sleep(5)
                if f.is_file():
                    print(f"  [*] 5s 后文件仍在: {f.stat().st_size} B")
                    rec["still_exists_after_5s"] = True
                else:
                    print(f"  [*] 5s 后文件已消失（企微已 move 走）")
                    rec["still_exists_after_5s"] = False
                rec["ok"] = True
                rec["dry_run_complete"] = True

            return rec

        time.sleep(0.05)

    print("[!] 120s 超时，未检测到新 silk")
    rec["reason"] = "timeout"
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="poc_staged_voice.json", help="staged voice json 路径")
    ap.add_argument("--dry-run", action="store_true", help="只报告，不覆写（测试文件锁）")
    ap.add_argument("--once", action="store_true", help="注入一次后退出（默认）")
    args = ap.parse_args()

    staged = load_staged(args.source)
    if not staged:
        print(f"[!] 无法加载 {args.source}")
        return 1

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rec = inject_once(staged, dry_run=args.dry_run)
    out = OUT_DIR / f"m3b_inject_{ts}.json"
    out.write_text(json.dumps({"args": vars(args), "staged": staged, "result": rec},
                               ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] 结果 → {out.name}")
    if rec.get("ok") and not rec.get("dry_run"):
        print("[✓] 注入完成 — 请观察企微气泡是否为语音条")
    elif rec.get("reason") == "file_locked":
        print("[✗] 文件锁定 — M3b-A 不可行，需走 M3b-B（虚拟音频）或 M3b-C（NativeFunction）")
    return 0 if rec.get("ok") else 1

if __name__ == "__main__":
    sys.exit(main())
