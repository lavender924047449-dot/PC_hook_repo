"""
BatchRunner — 串行执行 SendTask 队列。

策略 (严格模式)：
    - 首任务立即执行；后续每条前先 Scheduler.sleep_next_interval()
    - 每条发送前检查工作时段 + 配额，任何一项不满足 → 立即停止
    - 严格模式：单任务失败 → 立即停止 (不重试)
    - 发送成功 → 记录到 Scheduler，进入下一条

结束时把结果落到 runtime/reports/report_<ts>.csv
"""

from __future__ import annotations

import csv
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path

from loguru import logger

from app.automation.sender import VoiceSender
from app.config import resolve_path
from app.orchestrator.scheduler import (
    OutsideWorkingHours,
    QuotaExceeded,
    Scheduler,
)
from app.orchestrator.task import SendTask, TaskStatus


ProgressCb = Callable[[SendTask, int, int], None]


class BatchAborted(RuntimeError):
    """严格模式下，任务失败或配额/时段不满足时抛出"""


class BatchRunner:
    def __init__(
        self,
        sender: VoiceSender,
        scheduler: Scheduler,
        *,
        strict: bool = True,
        report_dir: Path | str = "runtime/reports",
        progress_cb: ProgressCb | None = None,
    ) -> None:
        self.sender = sender
        self.scheduler = scheduler
        self.strict = strict
        self.report_dir = resolve_path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.progress_cb = progress_cb

    def run(self, tasks: list[SendTask]) -> list[SendTask]:
        n = len(tasks)
        logger.info(f"BatchRunner 启动: {n} 个任务  严格模式={self.strict}")

        aborted = False
        for i, task in enumerate(tasks):
            # 首条不等，后续走随机间隔
            if i > 0:
                self.scheduler.sleep_next_interval()

            # 前置检查
            try:
                self.scheduler.check_working_hours()
                self.scheduler.check_quota()
            except (OutsideWorkingHours, QuotaExceeded) as e:
                logger.error(f"停止批处理: {e}")
                task.mark_skipped(str(e))
                # 剩余全标 SKIPPED
                for rest in tasks[i:]:
                    if rest.status == TaskStatus.PENDING:
                        rest.mark_skipped(str(e))
                aborted = True
                break

            # 发送
            task.mark_running()
            self._notify(task, i + 1, n)
            try:
                result = self.sender.send(task.contact, task.audio)
                task.mark_sent(result.duration_s)
                self.scheduler.record_sent()
                stats = self.scheduler.stats()
                logger.info(
                    f"[{i + 1}/{n}] ✓ {task.contact}   "
                    f"1h={stats['sent_last_hour']}  24h={stats['sent_last_24h']}"
                )
            except Exception as e:
                logger.exception(f"[{i + 1}/{n}] ✗ {task.contact}: {e}")
                task.mark_failed(e)
                self._notify(task, i + 1, n)
                if self.strict:
                    logger.error("严格模式：首个失败即停")
                    for rest in tasks[i + 1:]:
                        rest.mark_skipped("aborted by previous failure")
                    aborted = True
                    break

            self._notify(task, i + 1, n)

        report_path = self._write_report(tasks)
        logger.info(f"报告已保存: {report_path}")
        self._print_summary(tasks, aborted)
        return tasks

    def _notify(self, task: SendTask, idx: int, total: int) -> None:
        if self.progress_cb:
            try:
                self.progress_cb(task, idx, total)
            except Exception as e:
                logger.debug(f"progress_cb 抛异常，忽略: {e}")

    def _write_report(self, tasks: Iterable[SendTask]) -> Path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.report_dir / f"report_{ts}.csv"
        rows = [t.summary() for t in tasks]
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _print_summary(self, tasks: list[SendTask], aborted: bool) -> None:
        counts: dict[str, int] = {}
        for t in tasks:
            counts[t.status.value] = counts.get(t.status.value, 0) + 1
        parts = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        prefix = "🟡 中止" if aborted else "🟢 完成"
        logger.info(f"{prefix}  {parts}")
