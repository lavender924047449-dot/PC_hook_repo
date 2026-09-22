"""
Spike 5 (Stage 4.5.5.1.7) — 交互式验证:PC 企微缓存扫描 → AssetLibrary 自动入库.

用法:
    # 用 auto_detect (自动挑活跃账号) + 60 秒轮询
    python spike5_cache_scan_watch.py

    # 指定账号
    python spike5_cache_scan_watch.py --account 1688857496937113

    # 列一下有哪些账号可选
    python spike5_cache_scan_watch.py --list

    # 把 Voice 也扫上 (默认跳过, 4.5.5 阶段 voice 不走 B 模型)
    python spike5_cache_scan_watch.py --include-voice

    # 短一点的 timeout, 或"抢到就走"
    python spike5_cache_scan_watch.py --timeout 20 --stop-on-first

流程:
    1. 脚本启动后, 给你 5 秒切到 PC 企微
    2. 打开 "文件传输助手", 从磁盘拖入 1~3 个测试文件 (jpg/mp4/pdf)
    3. 脚本轮询缓存, 发现新文件自动入库并打印 tag / 路径 / hash
    4. 60 秒 timeout, 或用 Ctrl+C 手动结束
    5. 库文件默认写到 runtime/asset_library.json

注意:
    * Voice 是 SILK V3, 虚拟麦克风吃不了, 默认 skip; 需 --include-voice 打开
    * 库是幂等的, 同一份文件多次跑 tag 不会重复
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Windows 控制台默认 GBK, 中文会乱码; 强制切 UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from loguru import logger

from app.messaging.asset_library import AssetLibrary
from app.messaging.cache_scanner import WeComCacheScanner


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true",
                    help="列出所有企微账号 (按缓存文件数排序)")
    ap.add_argument("--account", default=None,
                    help="指定账号 ID; 不给就 auto_detect")
    ap.add_argument("--wxwork-root", default=None,
                    help="覆盖默认 WXWork 根目录 "
                         "(默认 %%USERPROFILE%%/Documents/WXWork)")
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="轮询秒数 (默认 60)")
    ap.add_argument("--poll", type=float, default=1.5,
                    help="轮询间隔秒 (默认 1.5)")
    ap.add_argument("--stop-on-first", action="store_true",
                    help="抢到第一批新文件就退出")
    ap.add_argument("--include-voice", action="store_true",
                    help="也扫 Voice/ (默认跳过, silk 不能直接用)")
    ap.add_argument("--decode-silk", action="store_true",
                    help="扫到 .silk 时自动用 vendor/silk/silk_v3_decoder.exe "
                         "转 wav 并入库 (隐含 --include-voice)")
    ap.add_argument("--lib", default="runtime/asset_library.json",
                    help="AssetLibrary JSON 路径 (相对项目根)")
    args = ap.parse_args()

    root = Path(args.wxwork_root) if args.wxwork_root else None

    # ---------- --list ---------- #
    if args.list:
        accts = WeComCacheScanner.list_accounts(root)
        if not accts:
            print("✗ 未发现任何企微账号目录")
            return 2
        print("发现账号:")
        for i, (acct, n) in enumerate(accts):
            marker = " ★" if i == 0 else ""
            print(f"  {acct}   files={n}{marker}")
        return 0

    # ---------- 构造 scanner ---------- #
    silk_dec = None
    if args.decode_silk:
        try:
            from app.audio.silk_decoder import SilkDecoder
            silk_dec = SilkDecoder()
            print(f"  ↳ SILK 解码器 ready: {silk_dec.silk_exe.name}")
        except Exception as e:
            print(f"✗ 初始化 SilkDecoder 失败: {e}")
            return 3
    skip = [] if (args.include_voice or args.decode_silk) else ["Voice"]

    try:
        if args.account:
            actual_root = root or WeComCacheScanner.DEFAULT_WXWORK_ROOT
            scanner = WeComCacheScanner(
                actual_root / args.account,
                skip_subdirs=skip, silk_decoder=silk_dec,
            )
        else:
            scanner = WeComCacheScanner.auto_detect(
                root, skip_subdirs=skip, silk_decoder=silk_dec,
            )
    except (FileNotFoundError, NotADirectoryError) as e:
        print(f"✗ 无法初始化 scanner: {e}")
        return 3

    print("=" * 72)
    print(f"  账号:      {scanner.account_dir.name}")
    print(f"  Cache 根:  {scanner.cache_root}")
    print(f"  Skip:      {sorted(scanner.skip_subdirs) or '(全扫)'}")
    print(f"  库文件:    {args.lib}")
    print(f"  轮询:      {args.timeout}s @ {args.poll}s")
    print("=" * 72)

    # ---------- 加载库 ---------- #
    lib = AssetLibrary.load(args.lib)
    print(f"  ↳ 库中已有 {len(lib)} 条")

    # ---------- 基线 ---------- #
    baseline = scanner.snapshot()
    print(f"  ↳ 缓存快照基线: {len(baseline)} 个文件")

    # ---------- 提示用户 ---------- #
    print()
    print("请在 5 秒内切到 PC 企微 → 打开「文件传输助手」→ 拖入/发送 1~3 个文件")
    print("(推荐: 一张 .jpg + 一个 .pdf + 一段 .mp4, 别发 Voice 除非加了 --include-voice)")
    for i in (5, 4, 3, 2, 1):
        print(f"  {i}...", end="\r", flush=True)
        time.sleep(1)
    print(" " * 20)

    # ---------- watch ---------- #
    print(f">>> 开始轮询, {args.timeout}s...")
    try:
        result = scanner.watch_and_register(
            lib,
            timeout_s=args.timeout,
            poll_interval_s=args.poll,
            stop_on_first_batch=args.stop_on_first,
        )
    except KeyboardInterrupt:
        print("\n! 用户中断")
        result = None

    # ---------- 保存 ---------- #
    lib.save()

    # ---------- 报告 ---------- #
    print()
    print("=" * 72)
    if not result or not result.new_files:
        print("  ⚠ 未检测到任何新文件")
        print("     可能原因: 你还没发到 FTA / 账号不对 / 缓存写入延迟")
        return 4

    print(f"  ✅ 新文件 {len(result.new_files)},  入库 {len(result.registered)}")
    if result.skipped_by_type:
        print(f"     跳过: {result.skipped_by_type} "
              f"(--include-voice 可解锁 Voice)")
    print()
    print("  Registered:")
    for e in result.registered:
        print(f"    · {e.tag}")
        print(f"        type={e.semantic_type.value}  sha1={e.sha1[:12]}...")
        print(f"        path={e.source_path}")
    if result.skipped_by_type:
        print()
        print("  Skipped:")
        for cf in result.new_files:
            if cf.subdir in scanner.skip_subdirs:
                print(f"    · [{cf.subdir}] {cf.path.name}   size={cf.size}")

    print()
    print(f"  库已写入 → {lib.path}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消")
        sys.exit(130)
