"""待发送清单模型与持久化。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from app.config import resolve_path

QueueStatus = Literal["pending", "running", "sent", "failed", "paused"]


@dataclass
class QueueItem:
    id: str
    material_code: str
    target: str
    note: str = ""
    status: QueueStatus = "pending"
    error: str = ""
    source_account: str = ""
    created_at: str = ""
    updated_at: str = ""

    def touch(self) -> None:
        self.updated_at = datetime.now().isoformat(timespec="seconds")
        if not self.created_at:
            self.created_at = self.updated_at


class SendQueue:
    def __init__(self, path: str | Path = "runtime/send_queue.json") -> None:
        self.path = resolve_path(path)
        self._items: list[QueueItem] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self._items = []
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._items = [QueueItem(**x) for x in raw.get("items", [])]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"items": [x.__dict__ for x in self._items]}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def items(self, *, source_account: str | None = None) -> list[QueueItem]:
        if source_account is None:
            return list(self._items)
        return [x for x in self._items if x.source_account == source_account]

    def add(self, item: QueueItem) -> None:
        item.touch()
        self._items.append(item)
        self.save()

    def remove(self, item_id: str) -> None:
        self._items = [x for x in self._items if x.id != item_id]
        self.save()

    def update_status(self, item_id: str, status: QueueStatus, *, error: str = "") -> None:
        for x in self._items:
            if x.id == item_id:
                x.status = status
                x.error = error
                x.touch()
                self.save()
                return
        raise KeyError(f"队列项不存在: {item_id}")
