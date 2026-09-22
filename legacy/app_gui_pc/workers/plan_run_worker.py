"""
PlanRunWorker (Stage 5.3) — 在后台线程执行 PlanRunner.

设计:
    * QObject + Signal: 与主线程 UI 解耦.
    * 支持 stop(): 通过 Event 请求中断 (PlanRunner 在步间/等待期间响应).
    * dry-run 不连 ADB; 真跑才建立 AdbSession.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from app.config import AppConfig, load_config, resolve_path
from app.messaging import (
    AssetLibrary,
    BatchPlan,
    PlanRunner,
    SendContext,
    SenderRegistry,
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


@dataclass
class RunOptions:
    dry_run: bool = True
    loose: bool = False
    resume: bool = False
    ignore_schedule: bool = False
    no_jitter: bool = False
    keep_remote: bool = False
    limit_contacts: int = 0
    report_dir: str = "runtime/reports"


class PlanRunWorker(QObject):
    log = Signal(str)
    progress = Signal(int, int, str, str)   # idx, total, status, brief
    finished = Signal(dict)                  # summary dict
    failed = Signal(str)

    def __init__(
        self,
        plan: BatchPlan,
        options: RunOptions,
        config_path: Path | None = None,
    ) -> None:
        super().__init__()
        self._plan = plan
        self._options = options
        self._config_path = config_path
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()
        self.log.emit("收到停止请求，等待当前步骤收尾…")

    def _should_stop(self) -> bool:
        return self._stop_event.is_set()

    @Slot()
    def run(self) -> None:
        try:
            cfg = load_config(self._config_path) if self._config_path else load_config()
            summary = self._run_with_config(cfg)
            self.finished.emit(summary)
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")

    def _run_with_config(self, cfg: AppConfig) -> dict:
        reg = self._build_registry()
        self._check_supported_types(reg)

        strict = not self._options.loose
        scheduler = Scheduler(cfg.schedule, jitter=not self._options.no_jitter)
        asset_library = AssetLibrary.load()

        self.log.emit(
            f"开始执行: {self._plan.meta.name} | "
            f"演练模式={self._options.dry_run} 严格模式={strict} 断点续发={self._options.resume}"
        )

        if self._options.dry_run:
            ctx = SendContext(
                dev=None,
                nav=None,
                cfg=cfg,
                file_store=None,
                asset_library=asset_library,
            )
            runner = PlanRunner(
                plan=self._plan,
                registry=reg,
                ctx=ctx,
                scheduler=scheduler,
                strict=strict,
                jitter=not self._options.no_jitter,
                dry_run=True,
                ignore_schedule=True,
                resume=self._options.resume,
                limit_contacts=self._options.limit_contacts,
                report_dir=self._options.report_dir,
                progress_cb=self._on_step,
                should_stop=self._should_stop,
            )
            steps = runner.run()
            return self._build_summary(steps, runner.last_report_paths)

        from app.automation.navigator import WeComNavigator
        from app.device.adb import AdbSession
        from app.device.file_store import AndroidFileStore

        with AdbSession(
            port=cfg.device.adb_port,
            connect_timeout=cfg.device.connect_timeout,
        ) as sess:
            nav = WeComNavigator(sess.dev, cfg.locators)
            store = AndroidFileStore(sess.adb)
            ctx = SendContext(
                dev=sess.dev,
                nav=nav,
                cfg=cfg,
                file_store=store,
                asset_library=asset_library,
            )
            runner = PlanRunner(
                plan=self._plan,
                registry=reg,
                ctx=ctx,
                scheduler=scheduler,
                strict=strict,
                jitter=not self._options.no_jitter,
                dry_run=False,
                ignore_schedule=self._options.ignore_schedule,
                resume=self._options.resume,
                limit_contacts=self._options.limit_contacts,
                report_dir=self._options.report_dir,
                progress_cb=self._on_step,
                should_stop=self._should_stop,
            )
            steps = runner.run()

            if not self._options.keep_remote and store.all_remotes():
                store.cleanup()
            asset_library.save()
            return self._build_summary(steps, runner.last_report_paths)

    def _on_step(self, step, idx: int, total: int) -> None:
        brief = f"{step.kind.value} task#{step.task_index + 1} msg#{step.msg_index + 1} -> {step.contacts}"
        self.progress.emit(idx, total, step.status.value, brief)
        if step.status.value in ("failed", "skipped"):
            err = step.error or ""
            self.log.emit(f"[{idx}/{total}] {step.status.value.upper()} {brief} {err}".strip())
        elif step.status.value == "sent":
            self.log.emit(f"[{idx}/{total}] SENT {brief}")
        elif step.status.value == "running":
            self.log.emit(f"[{idx}/{total}] RUNNING {brief}")

    def _build_registry(self) -> SenderRegistry:
        reg = SenderRegistry()
        reg.register(TextSender())
        reg.register(ImageSender())
        reg.register(VideoSender())
        reg.register(FileSender())
        reg.register(VoiceSender())
        reg.register(ForwardSender())
        reg.register(ContactCardSender())
        reg.register(StickerSender())
        return reg

    def _check_supported_types(self, reg: SenderRegistry) -> None:
        unsupported: set = set()
        for task in self._plan.tasks:
            for m in task.messages:
                if m.type not in reg:
                    unsupported.add(m.type)
        if unsupported:
            names = ", ".join(sorted(t.value for t in unsupported))
            raise NotImplementedError(f"以下 message type 无 sender: {names}")

    def _build_summary(self, steps, report_paths) -> dict:
        counts: dict[str, int] = {}
        for s in steps:
            counts[s.status.value] = counts.get(s.status.value, 0) + 1
        reports = [str(resolve_path(p)) for p in report_paths]
        return {
            "counts": counts,
            "reports": reports,
            "stopped": self._stop_event.is_set(),
        }

