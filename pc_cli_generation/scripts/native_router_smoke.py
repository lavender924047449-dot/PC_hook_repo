"""native_router 真机 smoke 测试脚本（取代 runtime/wecom_re/hijack_v1_safe.py）

用途
----
在真实企微进程上跑一次 conv_id hijack，验证 :class:`app.pc_wecom.native_router.NativeRouter`
在生产环境中工作正常。**不修改产品代码，纯观察 + 一次 hijack**。

用法::

    python scripts/native_router_smoke.py --from S:...ORIG... --to S:...DEST...
    python scripts/native_router_smoke.py --pid 22184 --from S:... --to S:... --timeout 60

注意
----
* 需要 wxwork.exe 在跑（脚本会自动找 PID）
* ``from`` / ``to`` 长度必须相同（通常都是 35，即 ``S:{16}_{16}``）
* 首次运行前建议先跑 ``runtime/wecom_re/list_conv_ids.py`` 列出可用 conv_id
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.pc_wecom.native_router import (  # noqa: E402
    DEFAULT_VTABLE_OFFSET,
    NativeRouter,
)


def _resolve_pid() -> int:
    """自动找占内存最大的 wxwork.exe 主进程。"""
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-Process WXWork -ErrorAction SilentlyContinue | "
            "Sort-Object WorkingSet64 -Descending | "
            "Select-Object -First 1 -ExpandProperty Id",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    pid_s = (result.stdout or "").strip()
    if not pid_s:
        raise SystemExit("[!] no WXWork.exe running")
    return int(pid_s)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pid", type=int, default=None, help="wxwork.exe PID（省略时自动检测）")
    ap.add_argument("--from", dest="from_conv", required=True,
                    help="原 conv_id（严格匹配才 hijack）")
    ap.add_argument("--to", dest="to_conv", required=True,
                    help="重定向目标 conv_id（长度必须与 from 相同）")
    ap.add_argument("--timeout", type=int, default=60,
                    help="最长扫描时间（秒）")
    ap.add_argument("--interval-ms", type=int, default=150,
                    help="扫描间隔（ms）")
    ap.add_argument("--max-patches", type=int, default=None,
                    help="命中 N 次后自动停止")
    ap.add_argument("--vtable-offset", type=lambda s: int(s, 0), default=DEFAULT_VTABLE_OFFSET,
                    help=f"PostSendMessageTask2 vtable 偏移（默认 {DEFAULT_VTABLE_OFFSET:#x}）")
    ap.add_argument("--out-dir", type=Path,
                    default=Path(__file__).resolve().parent.parent / "runtime" / "wecom_re",
                    help="report JSON 输出目录")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(args.from_conv) != len(args.to_conv):
        raise SystemExit(
            f"[!] --from ({len(args.from_conv)}) 与 --to ({len(args.to_conv)}) 长度不同"
        )

    pid = args.pid or _resolve_pid()
    print(f"[*] target PID  = {pid}")
    print(f"[*] from        = {args.from_conv!r}")
    print(f"[*] to          = {args.to_conv!r}")
    print(f"[*] timeout     = {args.timeout}s  interval = {args.interval_ms}ms  "
          f"max_patches = {args.max_patches}")

    router = NativeRouter(
        pid=pid,
        vtable_offset=args.vtable_offset,
        scan_interval_ms=args.interval_ms,
    )

    try:
        router.attach()
    except Exception as e:  # noqa: BLE001
        print(f"[!] attach failed: {e}")
        return 2
    print(f"[*] attached, agent base = {router.agent_base}")

    try:
        handle = router.arm(
            from_conv_id=args.from_conv,
            to_conv_id=args.to_conv,
            timeout_sec=args.timeout,
            max_patches=args.max_patches,
        )
        print("[*] armed. 现在去 UI 里做转发（转发的目标联系人应对应 --from），"
              "命中后消息会被重定向到 --to")
        report = handle.wait(timeout=args.timeout + 10)
    finally:
        router.detach()

    # 打印结果
    print()
    print("=" * 80)
    print(f"[+] scans_done       = {report.scans_done}")
    print(f"[+] tasks_seen_unique = {report.tasks_seen_unique}")
    print(f"[+] tasks_matched    = {report.tasks_matched}")
    print(f"[+] tasks_patched    = {report.tasks_patched}")
    print(f"[+] duration_sec     = {report.duration_sec:.2f}")
    print(f"[+] timed_out        = {report.timed_out}")
    print(f"[+] stopped          = {report.stopped}")
    if report.error:
        print(f"[!] error            = {report.error}")

    # 落地 report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / f"native_router_smoke_{ts}.json"
    out_path.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n[+] full report → {out_path}")

    # 提示用户
    orig_uin = args.from_conv.split("_")[-1] if "_" in args.from_conv else "?"
    hij_uin = args.to_conv.split("_")[-1] if "_" in args.to_conv else "?"
    print()
    print("[!] 请人工确认：")
    print(f"    原联系人 (uin={orig_uin}) 应该 没有 收到消息")
    print(f"    hijack 目标 (uin={hij_uin}) 应该 收到 消息")

    if report.tasks_patched > 0:
        return 0
    if report.timed_out:
        return 3
    return 1


if __name__ == "__main__":
    sys.exit(main())
