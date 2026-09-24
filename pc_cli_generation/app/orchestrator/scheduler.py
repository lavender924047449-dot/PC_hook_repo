"""
调度器 — 控制"两条任务之间的间隔"、"工作时段"、"频率上限"。

- 随机间隔 (min_interval_s, max_interval_s) 之间
- 工作时段 [start_hour, end_hour) 24 小时制
- 每小时 / 每日上限 (软限制：超限时报错停止)
"""

from __future__ import annotations

import random
import time
from collections import deque
from datetime import datetime, timedelta

from loguru import logger

from app.config import ScheduleConfig


class QuotaExceeded(RuntimeError):
    pass


class OutsideWorkingHours(RuntimeError):
    pass


class Scheduler:
    def __init__(self, cfg: ScheduleConfig, *, jitter: bool = True) -> None:
        self.cfg = cfg
        self.jitter = jitter
        # 记录成功发送时刻，用于滚动窗口计数
        self._sent_timestamps: deque[datetime] = deque()

    # ---------- 工作时段 ---------- #
    def check_working_hours(self, now: datetime | None = None) -> None:
        now = now or datetime.now()
        start, end = self.cfg.working_hours
        if not (start <= now.hour < end):
            raise OutsideWorkingHours(
                f"当前 {now.strftime('%H:%M')} 不在工作时段 [{start}:00, {end}:00)"
            )

    # ---------- 配额 ---------- #
    def _prune(self, now: datetime) -> None:
        # 删掉超过 24h 的记录（我们只需要 24h 窗口）
        cutoff = now - timedelta(hours=24)
        while self._sent_timestamps and self._sent_timestamps[0] < cutoff:
            self._sent_timestamps.popleft()

    def check_quota(self, now: datetime | None = None) -> None:
        now = now or datetime.now()
        self._prune(now)
        daily = len(self._sent_timestamps)
        hourly = sum(1 for t in self._sent_timestamps if t >= now - timedelta(hours=1))

        if daily >= self.cfg.daily_limit:
            raise QuotaExceeded(
                f"已达每日上限 {self.cfg.daily_limit} 条"
            )
        if hourly >= self.cfg.hourly_limit:
            raise QuotaExceeded(
                f"已达每小时上限 {self.cfg.hourly_limit} 条 (当前小时 {hourly} 条)"
            )

    def record_sent(self) -> None:
        self._sent_timestamps.append(datetime.now())

    def stats(self) -> dict:
        now = datetime.now()
        self._prune(now)
        return {
            "sent_last_hour": sum(
                1 for t in self._sent_timestamps if t >= now - timedelta(hours=1)
            ),
            "sent_last_24h": len(self._sent_timestamps),
        }

    # ---------- 间隔等待 ---------- #
    def sleep_next_interval(self) -> float:
        """返回本次等待的秒数"""
        lo, hi = self.cfg.min_interval_s, self.cfg.max_interval_s
        if not self.jitter or lo >= hi:
            wait = float(lo)
        else:
            wait = random.uniform(lo, hi)
        logger.info(f"等待 {wait:.1f}s 后发送下一条 …")
        time.sleep(wait)
        return wait
