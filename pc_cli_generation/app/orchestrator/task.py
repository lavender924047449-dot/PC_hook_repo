"""
SendTask — 单次发送任务的领域模型。

生命周期:
    PENDING → RUNNING → (SENT | FAILED | SKIPPED)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(slots=True)
class SendTask:
    contact: str
    audio: Path
    row_index: int = 0                 # 在 CSV 里的行号 (1-based)，便于报错定位
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    error: str | None = None
    sent_at: datetime | None = None
    duration_s: float | None = None

    def mark_running(self) -> None:
        self.status = TaskStatus.RUNNING
        self.attempts += 1

    def mark_sent(self, duration_s: float) -> None:
        self.status = TaskStatus.SENT
        self.sent_at = datetime.now()
        self.duration_s = duration_s
        self.error = None

    def mark_failed(self, err: BaseException | str) -> None:
        self.status = TaskStatus.FAILED
        self.error = str(err)

    def mark_skipped(self, reason: str) -> None:
        self.status = TaskStatus.SKIPPED
        self.error = reason

    # 便于 CSV/日志输出
    def summary(self) -> dict:
        return {
            "row": self.row_index,
            "contact": self.contact,
            "audio": str(self.audio),
            "status": self.status.value,
            "attempts": self.attempts,
            "sent_at": self.sent_at.isoformat(timespec="seconds") if self.sent_at else "",
            "duration_s": f"{self.duration_s:.2f}" if self.duration_s else "",
            "error": self.error or "",
        }
