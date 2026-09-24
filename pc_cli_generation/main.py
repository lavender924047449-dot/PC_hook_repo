"""
wecom-voice-blaster 入口 (Stage 5.4 已就绪)

子命令一览：
    check                              配置 / ffmpeg / 日志目录自检 (Stage 1)
    show-config                        打印当前生效的配置
    normalize <input> [-o out]         按 config.yaml 参数把音频转成标准 WAV
    send <contact> <audio>             单次发送一条消息 (Stage 3+, VoiceSender)
    batch <csv>                        老 CSV 批发 (Stage 4, 已被 plan-run 取代)
    plan <plan.json>                   加载 BatchPlan 并 stub 干跑 (Stage 4.5.1)
    plan-run <plan.json>               真实执行 BatchPlan (Stage 4.5.9, 全类型 sender)
    scan-cache [--list] [--timeout]    扫描 PC 企微本地缓存并入 AssetLibrary (Stage 4.5.5.1.7)
    forward <code> <target>            PC 企微 FTA 转发一条已编码素材（图/视/语音/文件/卡片）
    queue-run                          执行待发送清单（runtime/send_queue.json）
    conv-map                           维护 display_name → conv_id 映射
    gui [plan.json]                    启动 PySide6 GUI (Stage 5.1–5.4)

详见 README.md。
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from loguru import logger

from app.config import ensure_runtime_layout, load_config
from app.util.logging import _prepare_windows_console, setup_logging


def _init(config_path: Path | None) -> None:
    ensure_runtime_layout()
    cfg = load_config(config_path) if config_path else load_config()
    setup_logging(
        level=cfg.logging.level,
        log_dir=cfg.logging.resolved_dir(),
        keep_days=cfg.logging.keep_days,
    )


def _scan_lock_path() -> Path:
    from app.config import resolve_path
    return resolve_path("runtime/scan-cache.pid")


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if handle:
                kernel32.CloseHandle(handle)
                return True
            # ERROR_ACCESS_DENIED = 5 → 进程存在但无权查询
            if kernel32.GetLastError() == 5:
                return True
            return False
        except Exception:
            pass
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _acquire_scan_lock() -> Path | None:
    path = _scan_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            old = int((path.read_text(encoding="utf-8") or "0").strip())
        except ValueError:
            old = 0
        if old and old != os.getpid() and _pid_is_running(old):
            logger.error(
                f"已有 scan-cache 在运行（PID {old}）。请先在那个终端按 Ctrl+C；"
                "若无反应，请在任务管理器结束该 python.exe 后再启动。"
            )
            return None
    path.write_text(str(os.getpid()), encoding="utf-8")
    return path


def _release_scan_lock(lock: Path | None) -> None:
    if lock is None:
        return
    try:
        if lock.exists() and lock.read_text(encoding="utf-8").strip() == str(os.getpid()):
            lock.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------- 子命令 ---------------- #

def cmd_show_config(args: argparse.Namespace) -> int:
    cfg = load_config(args.config) if args.config else load_config()
    print(cfg.model_dump_json(indent=2))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    _init(args.config)
    cfg = load_config(args.config) if args.config else load_config()
    from app.audio.preprocessor import resolve_ffmpeg
    try:
        binp = resolve_ffmpeg(cfg.ffmpeg)
        logger.info(f"✓ ffmpeg 可用: {binp}")
    except Exception as e:
        logger.error(f"✗ ffmpeg 不可用: {e}")
        return 2
    logger.info("✓ 配置加载成功")
    logger.info("✓ 日志目录: " + str(cfg.logging.resolved_dir()))
    logger.info("Stage 1 check 全部通过")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    """批量发送：读 CSV → 串行发送 → 输出报告 (Stage 4 老路径, 建议改用 plan-run)"""
    _init(args.config)
    logger.warning(
        "`batch` 是 Stage 4 老 CSV 批发路径, 仅支持语音单类型; "
        "推荐改用 `python main.py plan-run <plan.json>` (Stage 4.5.9)"
    )
    cfg = load_config(args.config) if args.config else load_config()

    from app.automation.sender import VoiceSender
    from app.device.adb import AdbSession
    from app.orchestrator.csv_loader import load_tasks
    from app.orchestrator.runner import BatchRunner
    from app.orchestrator.scheduler import Scheduler

    tasks = load_tasks(args.csv, check_audio_exists=True)

    # 干跑：只解析 CSV，不真发送
    if args.dry_run:
        logger.info(f"[dry-run] 共 {len(tasks)} 个任务:")
        for t in tasks:
            logger.info(f"  · row {t.row_index}  {t.contact}  ← {t.audio}")
        return 0

    with AdbSession(
        port=cfg.device.adb_port,
        connect_timeout=cfg.device.connect_timeout,
    ) as sess:
        sender = VoiceSender.from_config(sess.dev, cfg)
        scheduler = Scheduler(cfg.schedule, jitter=not args.no_jitter)
        runner = BatchRunner(
            sender=sender,
            scheduler=scheduler,
            strict=not args.loose,
        )
        results = runner.run(tasks)

    failed = sum(1 for t in results if t.status.value == "failed")
    return 1 if failed else 0


def cmd_send(args: argparse.Namespace) -> int:
    """单次发送：给指定联系人/群发送一条预录制语音"""
    _init(args.config)
    cfg = load_config(args.config) if args.config else load_config()

    from app.automation.sender import VoiceSender
    from app.device.adb import AdbSession

    with AdbSession(
        port=cfg.device.adb_port,
        connect_timeout=cfg.device.connect_timeout,
    ) as sess:
        sender = VoiceSender.from_config(sess.dev, cfg)
        result = sender.send(args.contact, Path(args.audio))
        logger.info(f"完成: {result}")
    return 0


def cmd_plan_run(args: argparse.Namespace) -> int:
    """
    真实执行 BatchPlan (Stage 4.5.9: 走 PlanRunner, 完整批处理引擎).

    已实现 sender (Stage 4.5.8, MessageType 全覆盖):
      - Direct 类: TEXT / IMAGE / VIDEO / FILE / VOICE / CONTACT_CARD / STICKER
      - Forward 类: MINIPROGRAM / CHANNEL_VIDEO / LOCATION

    Options:
      --dry-run                只解析步骤, 不真调 sender (无 adb 也可跑)
      --limit-contacts N       每个 BroadcastTask 只跑前 N 个联系人 (调试)
      --no-jitter              类型化间隔固定用 min, 不随机
      --keep-remote            不清理 push 到设备的媒体文件
      --refresh-forward-assets Forward 阶段前先 forward_to_self 保鲜
      --strict / --loose       严格模式 (首失败即停) vs 宽松模式 (记录后继续)
                               默认 --strict
      --resume                 恢复上次未完成的进度 (跳过已 SENT 的 step)
      --ignore-schedule        跳过工作时段 / 配额门控 (调试; dry-run 默认跳过)
      --report-dir DIR         报告输出目录 (默认 runtime/reports)
    """
    _init(args.config)
    cfg = load_config(args.config) if args.config else load_config()

    from app.automation.navigator import WeComNavigator
    from app.device.adb import AdbSession
    from app.device.file_store import AndroidFileStore
    from app.messaging import (
        AssetLibrary,
        PlanRunner,
        SendContext,
        SenderRegistry,
        load_plan,
    )
    from app.messaging.senders import (
        ContactCardSender,
        FileSender,
        ForwardSender,
        ImageSender,
        StickerSender,
        TextSender,
        VideoSender,
        VoiceSender,
    )
    from app.orchestrator.scheduler import Scheduler

    plan = load_plan(args.plan)
    logger.info(f"── plan-run: {plan.meta.name} ──")
    logger.info(
        f"   tasks={len(plan.tasks)}  "
        f"unique_contacts={len(plan.unique_contacts())}  "
        f"messages={plan.total_messages()}  "
        f"total_sends={plan.total_sends()}"
    )

    # 已实现的 sender
    reg = SenderRegistry()
    reg.register(TextSender())
    reg.register(ImageSender())
    reg.register(VideoSender())
    reg.register(FileSender())
    reg.register(VoiceSender())
    reg.register(ForwardSender())
    reg.register(ContactCardSender())
    reg.register(StickerSender())

    # 检查 plan 里所有 type 是否都已实现
    unsupported: set = set()
    for task in plan.tasks:
        for m in task.messages:
            if m.type not in reg:
                unsupported.add(m.type)
    if unsupported:
        names = ", ".join(sorted(t.value for t in unsupported))
        raise NotImplementedError(f"以下 message type 无 sender: {names}")

    # 加载 AssetLibrary
    asset_library = AssetLibrary.load()
    logger.info(f"   asset_library: {len(asset_library)} 条")

    strict = not getattr(args, "loose", False)

    # ---- dry-run: 不连 adb, 直接走 PlanRunner 干跑 ---- #
    if args.dry_run:
        ctx = SendContext(
            dev=None, nav=None, cfg=cfg,
            file_store=None, asset_library=asset_library,
        )
        runner = PlanRunner(
            plan=plan, registry=reg, ctx=ctx,
            scheduler=Scheduler(cfg.schedule, jitter=not args.no_jitter),
            strict=strict,
            jitter=not args.no_jitter,
            dry_run=True,
            ignore_schedule=True,
            resume=args.resume,
            limit_contacts=args.limit_contacts,
            report_dir=args.report_dir,
        )
        results = runner.run()
        failed = sum(1 for s in results
                     if s.status.value in ("failed", "skipped"))
        return 1 if (strict and failed) else 0

    # ---- 真实运行: 连 adb ---- #
    with AdbSession(
        port=cfg.device.adb_port,
        connect_timeout=cfg.device.connect_timeout,
    ) as sess:
        nav = WeComNavigator(sess.dev, cfg.locators)
        store = AndroidFileStore(sess.adb)
        ctx = SendContext(
            dev=sess.dev, nav=nav, cfg=cfg,
            file_store=store, asset_library=asset_library,
        )

        # 可选: Forward 素材保鲜
        if args.refresh_forward_assets:
            _refresh_forward_assets(plan, nav, asset_library)

        runner = PlanRunner(
            plan=plan, registry=reg, ctx=ctx,
            scheduler=Scheduler(cfg.schedule, jitter=not args.no_jitter),
            strict=strict,
            jitter=not args.no_jitter,
            dry_run=False,
            ignore_schedule=args.ignore_schedule,
            resume=args.resume,
            limit_contacts=args.limit_contacts,
            report_dir=args.report_dir,
        )
        results = runner.run()

        # 收尾
        if not args.keep_remote and store.all_remotes():
            store.cleanup()
        asset_library.save()

    failed = sum(1 for s in results if s.status.value == "failed")
    return 1 if (strict and failed) else 0


def _refresh_forward_assets(plan, nav, asset_library) -> None:
    """
    Stage 4.5.5.4 保鲜循环:
      收集 plan 中所有转发类消息用到的 tag → 对每个 tag 调 forward_to_self
      → 更新 AssetEntry.last_refreshed_at.

    一次 open_fta, 循环内保鲜多个 tag (避免反复回 FTA).
    """
    from app.messaging import FORWARD_TYPES

    tags: list[str] = []
    seen: set[str] = set()
    for task in plan.tasks:
        for m in task.messages:
            if m.type in FORWARD_TYPES and m.tag and m.tag not in seen:
                seen.add(m.tag)
                tags.append(m.tag)

    if not tags:
        logger.info("── refresh: 无转发类素材, 跳过保鲜")
        return

    logger.info(f"── refresh: 保鲜 {len(tags)} 个 tag: {tags}")
    nav.open_fta()
    for tag in tags:
        try:
            entry = asset_library.get(tag)
        except KeyError:
            logger.warning(f"  ⚠ 跳过未知 tag: {tag}")
            continue
        locator = (entry.fta_locator or "").strip()
        if not locator:
            logger.warning(f"  ⚠ 跳过缺 fta_locator: {tag}")
            continue
        try:
            nav.forward_to_self(locator)
            entry.touch_refreshed()
            logger.info(f"  ✓ 已保鲜 {tag} ({locator!r})")
        except Exception as e:
            logger.error(f"  ✗ 保鲜失败 {tag}: {e}")


def cmd_plan(args: argparse.Namespace) -> int:
    """
    加载 BatchPlan JSON, 打印概要 + 干跑分发流程 (Stage 4.5.1).

    这一阶段只走 stub sender, 不真的操作企微. 目的:
      - 校验 JSON 结构
      - 展示"哪些消息会怎样发 (direct 逐人 / forward 一次多选)"
      - 展示类型化间隔的实际抽签数字
    """
    _init(args.config)

    from app.messaging import (
        BatchPlan,
        FORWARD_TYPES,
        SendContext,
        build_stub_registry,
        load_plan,
    )

    plan: BatchPlan = load_plan(args.plan)
    reg = build_stub_registry()
    ctx = SendContext()

    logger.info(f"── plan: {plan.meta.name} ──")
    if plan.meta.note:
        logger.info(f"   note: {plan.meta.note}")
    logger.info(
        f"   tasks={len(plan.tasks)}  "
        f"unique_contacts={len(plan.unique_contacts())}  "
        f"messages={plan.total_messages()}  "
        f"total_sends={plan.total_sends()}"
    )

    if args.summary_only:
        for i, t in enumerate(plan.tasks, 1):
            logger.info(
                f"  [{i}] {t.label or '(无标签)'}  "
                f"contacts={t.contacts}  msgs={[m.brief() for m in t.messages]}"
            )
        return 0

    # 干跑分发 (stub, 不真的 sleep 那么久，减到 0)
    for i, t in enumerate(plan.tasks, 1):
        logger.info(f"── Task {i}/{len(plan.tasks)}: {t.label or '(无标签)'}")
        for msg in t.messages:
            wait = plan.intervals.pick(msg.type, jitter=True)
            logger.info(
                f"  ⏱ 抽到等待 {wait:.1f}s   ▶  {msg.brief()}"
            )
            sender = reg.get(msg.type)
            if msg.type in FORWARD_TYPES:
                sender.send(ctx, t.contacts, msg)
            else:
                for c in t.contacts:
                    sender.send(ctx, [c], msg)

    logger.info("🟢 plan 干跑完成 (stub, 未连接企微)")
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    """
    启动 PySide6 GUI (Stage 5.1: Plan 浏览器).

    可选传入 plan.json 直接加载. 关闭窗口后返回 exit code.
    """
    _init(args.config)

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as e:
        logger.error(
            "未安装 PySide6, 请先: pip install \"PySide6>=6.8.0\"\n"
            f"原始错误: {e}"
        )
        return 2

    from legacy.app_gui_pc.main_window import MainWindow

    initial = Path(args.plan) if args.plan else None
    if initial is not None and not initial.exists():
        logger.error(f"plan 不存在: {initial}")
        return 2

    app = QApplication.instance() or QApplication(sys.argv)
    win = MainWindow(initial_plan_path=initial, config_path=args.config)
    win.show()
    return app.exec()


def cmd_scan_cache(args: argparse.Namespace) -> int:
    """
    扫描 PC 企微本地缓存, 自动入 AssetLibrary (Stage 4.5.5.1.7).

    典型流程:
      1. 打开 PC 企业微信, 保持登录状态
      2. 运行 `python main.py scan-cache --list` 确认账号
      3. 运行 `python main.py scan-cache --watch --echo-code`（默认一直监听，Ctrl+C 结束；默认扫描图片/视频/文件/语音）
      4. 切到 PC 企微「文件传输助手」，发送或转发素材
      5. 脚本发现新缓存或复用本地已有副本 → 回写编码

    需要限时退出时再加 `--timeout 60`。
    """
    _init(args.config)

    from app.messaging.asset_library import AssetLibrary
    from app.messaging.cache_scanner import WeComCacheScanner
    from app.pc_wecom import BubbleAnchorService, FtaCodeEcho, PCWeComNavigator, wire_capture_echo

    wxwork_root = Path(args.wxwork_root) if args.wxwork_root else None

    # ---------- --list ---------- #
    if args.list:
        accts = WeComCacheScanner.list_accounts(wxwork_root)
        if not accts:
            logger.error("未发现任何企微账号目录")
            return 2
        logger.info("发现账号 (按缓存文件数排序):")
        for i, (acct, n) in enumerate(accts):
            marker = " ★" if i == 0 else ""
            logger.info(f"  {acct}   files={n}{marker}")
        return 0

    lock = _acquire_scan_lock()
    if lock is None:
        return 5
    try:
        return _cmd_scan_cache_locked(args, wxwork_root)
    finally:
        _release_scan_lock(lock)


def _cmd_scan_cache_locked(args: argparse.Namespace, wxwork_root: Path | None) -> int:
    from app.messaging.asset_library import AssetLibrary
    from app.messaging.cache_scanner import WeComCacheScanner
    from app.pc_wecom import BubbleAnchorService, FtaCodeEcho, PCWeComNavigator, wire_capture_echo

    # ---------- 构造 scanner ---------- #
    silk_dec = None
    if args.decode_silk:
        try:
            from app.audio.silk_decoder import SilkDecoder
            silk_dec = SilkDecoder()
            logger.info(f"SILK 解码器 ready: {silk_dec.silk_exe.name}")
        except Exception as e:
            logger.error(f"初始化 SilkDecoder 失败: {e}")
            return 3

    skip = ["Voice"] if getattr(args, "skip_voice", False) else []

    try:
        if args.account:
            actual_root = wxwork_root or WeComCacheScanner.DEFAULT_WXWORK_ROOT
            scanner = WeComCacheScanner(
                actual_root / args.account,
                skip_subdirs=skip, silk_decoder=silk_dec,
                poll_fallback_s=args.poll,
            )
        else:
            scanner = WeComCacheScanner.auto_detect(
                wxwork_root, skip_subdirs=skip, silk_decoder=silk_dec,
                poll_fallback_s=args.poll,
            )
    except (FileNotFoundError, NotADirectoryError) as e:
        logger.error(f"无法初始化 scanner: {e}")
        return 3

    logger.info("── scan-cache ──")
    logger.info(f"  账号:      {scanner.account_dir.name}")
    logger.info(f"  Cache 根:  {scanner.cache_root}")
    logger.info(f"  Skip:      {sorted(scanner.skip_subdirs) or '(全扫)'}")
    logger.info(f"  库文件:    {args.lib}")
    timeout_label = "不限时（Ctrl+C 结束）" if args.timeout <= 0 else f"{args.timeout}s"
    logger.info(f"  轮询:      {timeout_label} @ {args.poll}s")
    logger.info(f"  watch:     {'ON' if args.watch else 'OFF'}")
    logger.info(f"  echo-code: {'ON' if args.echo_code else 'OFF'}"
                + (f" mode={args.echo_mode}" if args.echo_code else ""))

    lib = AssetLibrary.load(args.lib)
    logger.info(f"  库中已有 {len(lib)} 条")
    if args.echo_code:
        from app.pc_wecom.fta_code_echo import EchoMode
        mode: EchoMode = args.echo_mode
        navigator = PCWeComNavigator() if mode == "ui" else None

        # ── 尝试初始化 WeComMemoryReader（精确内存锚点，可选）────────────────
        memory_reader = None
        if not getattr(args, "no_memory_scan", False):
            try:
                from app.pc_wecom.wecom_memory_reader import WeComMemoryReader
                memory_reader = WeComMemoryReader()
                logger.info(
                    f"  内存锚点: WeComMemoryReader 就绪 "
                    f"(PID={memory_reader.pid}，首次扫描约 20s)"
                )
            except Exception as e:
                logger.debug(f"  WeComMemoryReader 不可用（将用文件时间戳兜底）: {e}")

        # ── 尝试初始化 NativeMsgIdReader（SQLite bind hook 产出的真实 msgid）─
        # 数据来源：`runtime/wecom_re/hook_sqlite_bind.py` 后台进程。
        # 若 JSON 不存在也不报错 —— 首次转发后由 hook 进程自动生成。
        native_reader = None
        try:
            from pathlib import Path as _P
            from app.pc_wecom.native_msgid_reader import NativeMsgIdReader
            _map = _P("runtime/wecom_re/native_msgid_map.json")
            native_reader = NativeMsgIdReader(_map)
            logger.info(
                f"  真实 msgid: NativeMsgIdReader 就绪 "
                f"(map={_map}，需并行运行 hook_sqlite_bind.py 才有数据)"
            )
        except Exception as e:  # noqa: BLE001
            logger.debug(f"  NativeMsgIdReader 不可用（不阻塞主流程）: {e}")

        anchor_svc = BubbleAnchorService(
            lib,
            memory_reader=memory_reader,
            native_reader=native_reader,
        )
        echo = FtaCodeEcho(
            anchor_svc,
            navigator=navigator,
            mode=mode,
            memory_reader=memory_reader,
        )
        wire_capture_echo(scanner, echo)
        if mode == "ui":
            logger.info("  已挂载编码回写器（UI 自动化，可能触发企微远程操作警告）")
        elif mode == "clipboard":
            logger.info("  已挂载编码回写器（仅剪贴板，不驱动企微界面）")
        else:
            logger.info("  已挂载编码回写器（剪贴板 + 前台粘贴，不挂 UIA、不点鼠标）")
    logger.info("  扫描范围:  Image / Video / File / Voice（仅捕捉真正的新缓存文件）")
    logger.info("  文件/视频: 缓存未落盘时请用 `python main.py register <文件路径>` 手动注册")

    baseline = scanner.snapshot()
    by_sub = {}
    for cf in baseline:
        by_sub[cf.subdir] = by_sub.get(cf.subdir, 0) + 1
    logger.info(f"  基线快照:  {len(baseline)} 个文件 {by_sub or '{}'}")

    # ---------- 可选倒计时（仅限时模式） ---------- #
    if not args.no_wait and args.timeout > 0:
        logger.info("请切到 PC 企微「文件传输助手」，随后开始限时监听")
        for i in (3, 2, 1):
            print(f"  {i}...", end="\r", flush=True)
            time.sleep(1)
        print(" " * 20)

    # ---------- watch ---------- #
    if args.timeout <= 0:
        logger.info(">>> 开始持续监听，按 Ctrl+C 结束 ...")
    else:
        logger.info(f">>> 开始监听, 最多 {args.timeout}s ...")
    try:
        if args.watch:
            result = scanner.watch_stream(
                lib,
                timeout_s=args.timeout,
                source_account=scanner.account_dir.name,
            )
        else:
            result = scanner.watch_and_register(
                lib,
                timeout_s=args.timeout,
                poll_interval_s=args.poll,
                stop_on_first_batch=args.stop_on_first,
            )
    except KeyboardInterrupt:
        logger.warning("用户中断轮询")
        lib.save()
        return 130

    lib.save()

    # ---------- 报告 ---------- #
    if not result.new_files:
        logger.warning("未检测到任何新文件 (是否未发到 FTA? 账号是否正确?)")
        return 4

    logger.info(
        f"✅ 新文件 {len(result.new_files)}, 入库 {len(result.registered)}, "
        f"跳过 {result.skipped_by_type or '(无)'}"
    )
    for e in result.registered:
        logger.info(
            f"  · {e.tag}   type={e.semantic_type.value}  "
            f"sha1={e.sha1[:12]}..  path={e.source_path}"
        )
    logger.info(f"库已写入 → {lib.path}")
    return 0


_SUFFIX_TO_TYPE: dict[str, str] = {
    # video
    ".mp4": "video", ".avi": "video", ".mkv": "video", ".mov": "video",
    ".wmv": "video", ".flv": "video",
    # voice
    ".silk": "voice", ".wav": "voice", ".mp3": "voice", ".m4a": "voice",
    ".ogg": "voice", ".amr": "voice",
    # image
    ".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image",
    ".bmp": "image", ".webp": "image", ".tiff": "image", ".tif": "image",
}


def _infer_message_type(path: Path):
    from app.messaging.types import MessageType
    suffix = path.suffix.lower()
    type_name = _SUFFIX_TO_TYPE.get(suffix)
    if type_name is not None:
        return MessageType(type_name)
    return MessageType.FILE


def cmd_register(args: argparse.Namespace) -> int:
    """手动注册本地文件到素材库，生成编码。不依赖企微缓存。"""
    _init(args.config)

    from app.messaging.asset_library import AssetLibrary

    lib = AssetLibrary.load(args.lib)
    files = [Path(p) for p in args.files]
    registered = []

    for fp in files:
        if not fp.exists():
            logger.error(f"文件不存在: {fp}")
            continue
        if not fp.is_file():
            logger.error(f"不是文件: {fp}")
            continue

        msg_type = _infer_message_type(fp)
        try:
            entry = lib.register_local(
                fp,
                msg_type,
                display_name=fp.stem,
                source_account=args.account or "manual",
            )
        except Exception as e:
            logger.error(f"注册失败 {fp}: {e}")
            continue

        registered.append(entry)
        logger.info(
            f"✅ {entry.material_code}  ← {fp.name}  "
            f"(type={entry.semantic_type.value}, sha1={entry.sha1[:12]}..)"
        )

    if not registered:
        logger.error("没有成功注册任何文件")
        return 1

    lib.save()
    logger.info(f"库已写入 → {lib.path}")

    if args.echo_code:
        codes = "\n".join(e.material_code for e in registered if e.material_code)
        if codes:
            from app.pc_wecom.fta_code_echo import copy_text_to_clipboard
            last_code = registered[-1].material_code or ""
            if copy_text_to_clipboard(last_code):
                logger.info(f"编码已复制到剪贴板: {last_code}")
            else:
                logger.warning("写入剪贴板失败，请手动复制")

    for e in registered:
        print(e.material_code)

    return 0


# 转发类素材的类型名映射
_FORWARD_TYPE_NAMES: dict[str, str] = {
    "miniprogram": "miniprogram",
    "mp": "miniprogram",
    "小程序": "miniprogram",
    "channel_video": "channel_video",
    "cv": "channel_video",
    "视频号": "channel_video",
    "location": "location",
    "loc": "location",
    "位置": "location",
    "contact_card": "contact_card",
    "card": "contact_card",
    "名片": "contact_card",
    "sticker": "sticker",
    "stk": "sticker",
    "表情": "sticker",
}


def cmd_register_forward(args: argparse.Namespace) -> int:
    """手动注册转发类素材（小程序/视频号/位置等），生成编码。"""
    _init(args.config)

    from app.messaging.asset_library import AssetLibrary
    from app.messaging.types import MessageType

    # 解析类型
    type_input = args.type.lower().strip()
    type_name = _FORWARD_TYPE_NAMES.get(type_input)
    if type_name is None:
        valid = sorted(set(_FORWARD_TYPE_NAMES.values()))
        logger.error(f"未知类型: {args.type!r}，可选: {valid}")
        return 1

    msg_type = MessageType(type_name)
    fta_locator = args.locator.strip()
    if not fta_locator:
        logger.error("定位词不能为空")
        return 1

    lib = AssetLibrary.load(args.lib)
    try:
        entry = lib.register_forward(
            msg_type,
            fta_locator,
            display_name=args.name or fta_locator,
            source_account=args.account or "manual",
        )
    except Exception as e:
        logger.error(f"注册失败: {e}")
        return 1

    lib.save()
    logger.info(
        f"✅ {entry.material_code}  ← {msg_type.value}:{fta_locator!r}  "
        f"(tag={entry.tag})"
    )
    logger.info(f"库已写入 → {lib.path}")

    # 回写编码
    code = entry.material_code or ""
    if args.echo_code and code:
        from app.pc_wecom.fta_code_echo import (
            copy_text_to_clipboard,
            paste_and_enter,
            wecom_is_foreground,
        )
        if copy_text_to_clipboard(code):
            if wecom_is_foreground() and paste_and_enter():
                logger.info(f"编码已粘贴发送: {code}")
            else:
                logger.info(f"编码已复制到剪贴板: {code}")
        else:
            logger.warning("写入剪贴板失败，请手动复制")

    print(code)
    return 0


def cmd_forward(args: argparse.Namespace) -> int:
    """PC 企微 FTA 转发一条已编码素材。类型无关：img/vid/voice/file/mp/... 同一条路径。"""
    _init(args.config)
    cfg = load_config(args.config) if args.config else load_config()

    from app.messaging.asset_library import AssetLibrary
    from app.pc_wecom.send_pipeline import build_send_pipeline

    lib = AssetLibrary.load(args.lib)
    enable_native = not args.no_native
    with build_send_pipeline(
        lib,
        app_config=cfg,
        pid=args.pid,
        enable_native=enable_native,
    ) as pipe:
        logger.info(
            f"── forward ── code={args.material_code} target={args.target} "
            f"native={pipe.native_enabled} pid={pipe.pid}"
        )
        res = pipe.send(
            args.material_code,
            args.target,
            conv_id=args.conv_id,
        )
    if res.ok:
        via = "native hijack" if res.via_native else "UIA 选人"
        logger.info(f"✅ 已转发 {res.material_code} → {res.target} ({via})")
        return 0
    logger.error(f"转发失败: {res.reason}")
    return 1


def cmd_queue_run(args: argparse.Namespace) -> int:
    """串行执行待发送清单。"""
    _init(args.config)
    cfg = load_config(args.config) if args.config else load_config()

    from app.messaging.asset_library import AssetLibrary
    from app.messaging.send_queue import SendQueue
    from app.orchestrator.scheduler import Scheduler
    from app.pc_wecom.send_pipeline import build_send_pipeline

    lib = AssetLibrary.load(args.lib)
    queue = SendQueue(args.queue or cfg.pc_wecom.send_queue_file)
    enable_native = not args.no_native
    with build_send_pipeline(
        lib,
        app_config=cfg,
        pid=args.pid,
        enable_native=enable_native,
    ) as pipe:
        scheduler = None
        if not args.ignore_schedule:
            scheduler = Scheduler(cfg.schedule)
        ex = pipe.make_queue_executor(
            queue,
            history_path=cfg.pc_wecom.send_history_file,
            scheduler=scheduler,
            ignore_schedule=args.ignore_schedule,
        )
        logger.info(
            f"── queue-run ── items={len(queue.items())} native={pipe.native_enabled}"
        )
        results = ex.run(source_account=args.source_account)
    sent = sum(1 for r in results if r.get("status") == "sent")
    failed = sum(1 for r in results if r.get("status") == "failed")
    logger.info(f"清单执行结束: sent={sent} failed={failed} total={len(results)}")
    return 0 if failed == 0 else 1


def cmd_conv_map(args: argparse.Namespace) -> int:
    """维护 {display_name → conv_id} 映射。"""
    _init(args.config)
    cfg = load_config(args.config) if args.config else load_config()

    from app.pc_wecom.contact_conv_resolver import ContactConvResolver

    resolver = ContactConvResolver(
        pid=int(args.pid or 0),
        cache_path=cfg.pc_wecom.conv_map_file,
    )
    if args.seed_pair:
        seed_name, seed_conv = args.seed_pair
        m = resolver.seed(seed_name, seed_conv)
        logger.info(f"已写入 {m.display_name} → {m.conv_id}")
        return 0
    if args.resolve:
        hit = resolver.resolve(args.resolve)
        if hit:
            print(hit)
            return 0
        logger.error(f"未解析到: {args.resolve}")
        return 1
    if args.refresh:
        if not args.pid:
            from app.pc_wecom.send_pipeline import resolve_wxwork_pid
            pid = resolve_wxwork_pid()
            if not pid:
                logger.error("未找到 WXWork.exe，无法扫堆")
                return 2
            resolver.pid = pid
        try:
            resolver.attach()
            mapping = resolver.refresh()
        finally:
            resolver.detach()
        logger.info(f"扫堆完成，映射 {len(mapping)} 条")
        for name, cid in mapping.items():
            logger.info(f"  {name} → {cid}")
        return 0
    mapping = resolver.mapping()
    if not mapping:
        logger.info("映射为空。可用 --seed 名称 conv_id 或 --refresh 扫堆。")
        return 0
    for name, cid in mapping.items():
        print(f"{name}\t{cid}")
    return 0


def cmd_normalize(args: argparse.Namespace) -> int:
    _init(args.config)
    cfg = load_config(args.config) if args.config else load_config()

    from app.audio.preprocessor import AudioPreprocessor
    pre = AudioPreprocessor(cfg.audio, cfg.ffmpeg)

    src = Path(args.input)
    result = pre.prepare(src, force=args.force)

    if args.output:
        # 用户显式指定输出，把预处理结果复制过去
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(result.dst.read_bytes())
        logger.info(f"→ 已复制到: {out}")
    else:
        logger.info(f"→ 输出: {result.dst}")

    logger.info(f"参数: {result.sample_rate}Hz  ch={result.channels}  "
                f"时长={result.duration_s:.2f}s")
    return 0


# ---------------- 主 ---------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wecom-voice-blaster",
        description="企业微信语音批量发送工具 (Android 模拟器方案)",
    )
    p.add_argument("--config", type=Path, default=None,
                   help="配置文件路径 (默认 ./config.yaml)")
    sub = p.add_subparsers(dest="command", required=True)

    # show-config
    s = sub.add_parser("show-config", help="打印当前生效的配置")
    s.set_defaults(func=cmd_show_config)

    # check
    s = sub.add_parser("check", help="配置 + ffmpeg 可用性自检")
    s.set_defaults(func=cmd_check)

    # send
    s = sub.add_parser(
        "send",
        help="单次发送一条语音气泡 (Stage 3, VoiceSender 单发路径)",
    )
    s.add_argument("contact", help="联系人或群的名称 (企微里显示的)")
    s.add_argument("audio", help="音频文件路径 (wav/mp3/...)")
    s.set_defaults(func=cmd_send)

    # batch
    s = sub.add_parser(
        "batch",
        help="老 CSV 批发 (Stage 4, 仅语音; 新流程请用 plan-run)",
    )
    s.add_argument("csv", help="CSV 文件路径 (列: contact,audio)")
    s.add_argument("--dry-run", action="store_true",
                   help="只解析 CSV，不真的发送")
    s.add_argument("--loose", action="store_true",
                   help="非严格模式：单条失败不中止 (默认严格)")
    s.add_argument("--no-jitter", action="store_true",
                   help="固定使用 min_interval_s，不做随机抖动")
    s.set_defaults(func=cmd_batch)

    # plan (Stage 4.5.1: 干跑打印 stub)
    s = sub.add_parser(
        "plan",
        help="加载 BatchPlan JSON 并 stub 干跑 (不连设备, Stage 4.5.1)",
    )
    s.add_argument("plan", help="plan.json 路径")
    s.add_argument("--summary-only", action="store_true",
                   help="只打印摘要, 不逐条模拟分发")
    s.set_defaults(func=cmd_plan)

    # plan-run (Stage 4.5.9: 全类型 sender + PlanRunner)
    s = sub.add_parser(
        "plan-run",
        help="真实执行 BatchPlan (Stage 4.5.9, 全 10 种消息类型)",
    )
    s.add_argument("plan", help="plan.json 路径")
    s.add_argument("--dry-run", action="store_true",
                   help="只解析步骤, 不连设备、不真发 (跳过工作时段门控)")
    s.add_argument("--limit-contacts", type=int, default=0,
                   help="每个 Task 只跑前 N 个联系人 (0=全部)")
    s.add_argument("--no-jitter", action="store_true",
                   help="类型化间隔固定取 min, 不随机抖动")
    s.add_argument("--keep-remote", action="store_true",
                   help="不清理 push 到设备的媒体文件 (调试用)")
    s.add_argument("--refresh-forward-assets", action="store_true",
                   help="Forward 阶段前先把所有 tag 转发给 FTA 自己 (保鲜)")
    # Stage 4.5.9 新增
    s.add_argument("--loose", action="store_true",
                   help="宽松模式: 单步失败后继续 (默认严格, 首失败即停)")
    s.add_argument("--resume", action="store_true",
                   help="从上次进度恢复 (跳过已 SENT 的 step)")
    s.add_argument("--ignore-schedule", action="store_true",
                   help="跳过工作时段/配额门控 (调试用; dry-run 默认跳过)")
    s.add_argument("--report-dir", default="runtime/reports",
                   help="报告输出目录 (默认 runtime/reports)")
    s.set_defaults(func=cmd_plan_run)

    # scan-cache (Stage 4.5.5.1.7)
    s = sub.add_parser(
        "scan-cache",
        help="扫描 PC 企微本地缓存并入 AssetLibrary (Stage 4.5.5.1.7)",
    )
    s.add_argument("--list", action="store_true",
                   help="只列出所有企微账号 (按缓存文件数排序), 不扫描")
    s.add_argument("--account", default=None,
                   help="指定账号 ID; 不给就 auto_detect (选文件最多的)")
    s.add_argument("--wxwork-root", default=None,
                   help="覆盖默认 WXWork 根目录 "
                        "(默认 %%USERPROFILE%%/Documents/WXWork)")
    s.add_argument("--timeout", type=float, default=0.0,
                   help="监听秒数；默认 0 表示一直监听直到 Ctrl+C。"
                        "需要限时退出时再传，例如 --timeout 60")
    s.add_argument("--poll", type=float, default=0.4,
                   help="轮询间隔秒 (默认 0.4；watch 模式下作为事件兜底间隔)")
    s.add_argument("--watch", action="store_true",
                   help="启用 watchdog 事件监听（并保留轮询兜底）")
    s.add_argument("--echo-code", action="store_true",
                   help="捕捉素材后立刻回写编码：默认写入剪贴板，"
                        "若企微已在前台则 Ctrl+V 发送（不挂 UIA）")
    s.add_argument(
        "--echo-mode",
        choices=["paste_if_focused", "clipboard", "ui"],
        default="paste_if_focused",
        help="编码回写方式：paste_if_focused=剪贴板+前台粘贴（默认，避开远程操作警告）；"
             "clipboard=只复制到剪贴板；ui=旧版鼠标/UIA 发送（会触发企微警告）",
    )
    s.add_argument("--stop-on-first", action="store_true",
                   help="抢到第一批新文件就退出")
    s.add_argument("--include-voice", action="store_true",
                   help="兼容旧开关：现在默认扫描 Voice/，不必再加")
    s.add_argument("--skip-voice", action="store_true",
                   help="不扫描 Voice/（默认会扫语音并生成 voice- 编码）")
    s.add_argument("--decode-silk", action="store_true",
                   help="扫到 .silk 时自动转 wav 入库 (隐含 --include-voice, "
                        "需要 vendor/silk/silk_v3_decoder.exe)")
    s.add_argument("--lib", default="runtime/asset_library.json",
                   help="AssetLibrary JSON 路径 (默认 runtime/asset_library.json)")
    s.add_argument("--no-wait", action="store_true",
                   help="跳过开始前的倒计时（持续监听模式默认没有倒计时）")
    s.add_argument("--no-memory-scan", action="store_true",
                   help="禁用 WeComMemoryReader 内存扫描（仅用文件时间戳作锚点，"
                        "适用于 WXWork.exe 未运行的场景）")
    s.set_defaults(func=cmd_scan_cache)

    # register (手动注册本地文件)
    s = sub.add_parser(
        "register",
        help="手动注册本地文件到素材库，生成编码（不依赖企微缓存）",
    )
    s.add_argument("files", nargs="+", help="一个或多个本地文件路径")
    s.add_argument("--lib", default="runtime/asset_library.json",
                   help="AssetLibrary JSON 路径 (默认 runtime/asset_library.json)")
    s.add_argument("--account", default=None,
                   help="来源账号标记 (默认 manual)")
    s.add_argument("--echo-code", action="store_true",
                   help="注册后把编码写入剪贴板")
    s.set_defaults(func=cmd_register)

    # register-forward (手动注册转发类素材)
    s = sub.add_parser(
        "register-forward",
        help="手动注册转发类素材（小程序/视频号/位置/名片/表情），生成编码",
    )
    s.add_argument("type",
                   help="素材类型: miniprogram(mp), channel_video(cv), "
                        "location(loc), contact_card(card), sticker(stk)")
    s.add_argument("locator",
                   help="FTA 定位词（小程序标题、位置名称等）")
    s.add_argument("--name", default=None,
                   help="显示名称（默认同 locator）")
    s.add_argument("--lib", default="runtime/asset_library.json",
                   help="AssetLibrary JSON 路径")
    s.add_argument("--account", default=None,
                   help="来源账号标记 (默认 manual)")
    s.add_argument("--echo-code", action="store_true",
                   help="注册后把编码写入剪贴板，若企微前台则粘贴发送")
    s.set_defaults(func=cmd_register_forward)

    # forward — PC FTA 转发一条已编码素材（类型无关）
    s = sub.add_parser(
        "forward",
        help="PC 企微 FTA 转发一条素材（语音/图片/视频/文件/卡片同一路径）",
    )
    s.add_argument("material_code", help="素材编码，如 img-3f8a2c9d1b47 / voice-...")
    s.add_argument("target", help="发送对象显示名（或占位联系人）")
    s.add_argument("--conv-id", default=None, help="真实目标 conv_id；省略则用 conv-map 解析")
    s.add_argument("--pid", type=int, default=None, help="WXWork.exe PID（省略则自动检测）")
    s.add_argument("--no-native", action="store_true", help="强制走 UIA 搜人，不用 hijack")
    s.add_argument("--lib", default="runtime/asset_library.json", help="素材库路径")
    s.set_defaults(func=cmd_forward)

    # queue-run — 执行待发送清单
    s = sub.add_parser("queue-run", help="执行待发送清单（runtime/send_queue.json）")
    s.add_argument("--queue", default=None, help="清单 JSON（默认配置 pc_wecom.send_queue_file）")
    s.add_argument("--source-account", default=None, help="只跑该 source_account")
    s.add_argument("--pid", type=int, default=None, help="WXWork.exe PID")
    s.add_argument("--no-native", action="store_true", help="强制走 UIA 搜人")
    s.add_argument("--ignore-schedule", action="store_true", help="跳过工作时段/配额")
    s.add_argument("--lib", default="runtime/asset_library.json", help="素材库路径")
    s.set_defaults(func=cmd_queue_run)

    # conv-map — display_name → conv_id
    s = sub.add_parser("conv-map", help="维护联系人显示名到 conv_id 的映射")
    s.add_argument("--seed", nargs=2, metavar=("NAME", "CONV_ID"), dest="seed_pair",
                   default=None, help="手动写入一条映射")
    s.add_argument("--resolve", default=None, help="查询一个显示名/uin 的 conv_id")
    s.add_argument("--refresh", action="store_true", help="对企微进程只读扫堆重建映射")
    s.add_argument("--pid", type=int, default=None, help="WXWork.exe PID")
    s.set_defaults(func=cmd_conv_map)

    # gui (Stage 5.1–5.4)
    s = sub.add_parser(
        "gui",
        help="启动 PySide6 图形界面 (Stage 5.1–5.4: 浏览/编辑/执行/素材库)",
    )
    s.add_argument("plan", nargs="?", default=None,
                   help="可选: 启动时自动加载的 plan.json")
    s.set_defaults(func=cmd_gui)

    # normalize
    s = sub.add_parser("normalize", help="按配置把音频转成标准 WAV")
    s.add_argument("input", help="输入音频 (wav/mp3/m4a/...)")
    s.add_argument("-o", "--output", help="输出路径 (可选，默认落到 runtime/prepared/)")
    s.add_argument("--force", action="store_true", help="即使缓存存在也重新处理")
    s.set_defaults(func=cmd_normalize)

    return p


def _gui_entry() -> int:
    """
    专门给 pyproject.toml `[project.gui-scripts]` 用的入口:
    等价于 `python main.py gui`, 便于打包成"双击运行"的 exe 时省掉子命令。

    也可以: `wecom-voice-blaster-gui` (安装后)
    或:     `python -m main gui`
    """
    _prepare_windows_console()
    parser = build_parser()
    args = parser.parse_args(["gui"])
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


def main() -> int:
    _prepare_windows_console()   # 先修好中文/ANSI，再解析参数
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        # 若已初始化 logger, 让 loguru 打印堆栈
        try:
            logger.exception(f"运行失败: {e}")
        except Exception:
            stream = sys.stderr or sys.stdout
            if stream is not None:
                print(f"运行失败: {e}", file=stream)
        return 1


if __name__ == "__main__":
    sys.exit(main())
