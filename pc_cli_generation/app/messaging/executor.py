"""清单执行器：串行消费 SendQueue 并写发送记录。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Callable

from app.config import resolve_path
from app.messaging.send_queue import QueueItem, SendQueue
from app.orchestrator.scheduler import Scheduler
from app.pc_wecom.forward_executor import ForwardExecutor


class QueueExecutor:
    def __init__(
        self,
        queue: SendQueue,
        forward_executor: ForwardExecutor,
        *,
        history_path: str | Path = "runtime/send_history.json",
        scheduler: Scheduler | None = None,
        ignore_schedule: bool = False,
        conv_resolver: object | None = None,
    ) -> None:
        self._queue = queue
        self._forward = forward_executor
        self._history_path = resolve_path(history_path)
        self._scheduler = scheduler
        self._ignore_schedule = ignore_schedule
        self._paused = False
        self._resolver = conv_resolver

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    def run(
        self,
        *,
        source_account: str | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> list[dict]:
        results: list[dict] = []
        sent_count = 0
        for item in self._queue.items(source_account=source_account):
            if item.status not in ("pending", "failed", "paused"):
                continue
            if self._paused or (should_stop and should_stop()):
                self._queue.update_status(item.id, "paused")
                continue

            if self._scheduler and not self._ignore_schedule:
                self._scheduler.check_working_hours()
                self._scheduler.check_quota()
                if sent_count > 0:
                    self._scheduler.sleep_next_interval()

            self._queue.update_status(item.id, "running")
            r = self._forward.forward(
                item.material_code,
                item.target,
                conv_id=self._resolve_conv_id(item.target),
            )
            if r.ok:
                self._queue.update_status(item.id, "sent")
                if self._scheduler:
                    self._scheduler.record_sent()
                sent_count += 1
            else:
                self._queue.update_status(item.id, "failed", error=r.reason)
            rec = self._to_record(item, ok=r.ok, error=r.reason)
            results.append(rec)
            self._append_history(rec)
        return results

    def retry_one(self, item_id: str) -> dict:
        items = [x for x in self._queue.items() if x.id == item_id]
        if not items:
            raise KeyError(f"队列项不存在: {item_id}")
        item = items[0]
        self._queue.update_status(item.id, "running")
        r = self._forward.forward(
            item.material_code,
            item.target,
            conv_id=self._resolve_conv_id(item.target),
        )
        if r.ok:
            self._queue.update_status(item.id, "sent")
        else:
            self._queue.update_status(item.id, "failed", error=r.reason)
        rec = self._to_record(item, ok=r.ok, error=r.reason)
        self._append_history(rec)
        return rec

    def _resolve_conv_id(self, target: str) -> str | None:
        """用 ContactConvResolver 把 SendQueue.target 显示名解析成 conv_id。"""
        resolver = self._resolver
        if resolver is None:
            return None
        resolve = getattr(resolver, "resolve", None)
        if not callable(resolve):
            return None
        hit = resolve(target)
        return str(hit).strip() if hit else None

    def _to_record(self, item: QueueItem, *, ok: bool, error: str) -> dict:
        return {
            "time": datetime.now().isoformat(timespec="seconds"),
            "id": item.id,
            "material_code": item.material_code,
            "target": item.target,
            "source_account": item.source_account,
            "status": "sent" if ok else "failed",
            "error": error,
            "note": item.note,
        }

    def _append_history(self, rec: dict) -> None:
        old = {"records": []}
        if self._history_path.exists():
            old = json.loads(self._history_path.read_text(encoding="utf-8"))
        old.setdefault("records", []).append(rec)
        self._history_path.parent.mkdir(parents=True, exist_ok=True)
        self._history_path.write_text(
            json.dumps(old, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
