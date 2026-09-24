"""
BroadcastTask / BatchPlan — GUI 编排产物 & JSON 存取。

数据模型（B 模式）:
    BatchPlan
      ├── intervals: TypedIntervals   (每类型的 min/max 秒)
      ├── tasks: [BroadcastTask, ...]
      │     ├── contacts: [str, ...]      # 一批客户 (1~N，1 = 单发)
      │     └── messages: [Message, ...]  # 这批人共享的消息序列
      └── meta: {name, created_at, ...}

JSON 示例见 samples/plan_example.json (Stage 4.5.4 会补)
"""

from __future__ import annotations

import json
import random
import time
from datetime import datetime
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field, field_validator

from app.messaging.types import Message, MessageType


# ---------- 类型化间隔 ---------- #

class TypedIntervals(BaseModel):
    """
    每种消息类型独立的 (min, max) 秒等待。
    发送第 N 条消息前, 等待 uniform(intervals[type_of_N])。
    """

    text: tuple[float, float] = (3.0, 6.0)
    image: tuple[float, float] = (6.0, 12.0)
    video: tuple[float, float] = (10.0, 18.0)
    file: tuple[float, float] = (6.0, 12.0)
    voice: tuple[float, float] = (8.0, 15.0)
    contact_card: tuple[float, float] = (6.0, 12.0)
    location: tuple[float, float] = (10.0, 18.0)
    sticker: tuple[float, float] = (4.0, 8.0)
    miniprogram: tuple[float, float] = (12.0, 22.0)
    channel_video: tuple[float, float] = (12.0, 22.0)

    @field_validator("*")
    @classmethod
    def _check_range(cls, v: tuple[float, float]) -> tuple[float, float]:
        lo, hi = v
        if lo < 0 or hi < lo:
            raise ValueError(f"非法区间: ({lo}, {hi})，要求 0 <= min <= max")
        return v

    def get(self, t: MessageType) -> tuple[float, float]:
        return getattr(self, t.value)

    def pick(self, t: MessageType, *, jitter: bool = True) -> float:
        """按类型抽一次等待秒数 (jitter=False 直接用 min)"""
        lo, hi = self.get(t)
        if not jitter or lo >= hi:
            return float(lo)
        return random.uniform(lo, hi)

    def sleep_for(
        self,
        t: MessageType,
        *,
        jitter: bool = True,
        log: bool = True,
    ) -> float:
        """
        按类型等待。返回实际睡了多少秒。
        对齐 orchestrator/scheduler.py 里已有的 sleep_next_interval 风格。
        """
        wait = self.pick(t, jitter=jitter)
        if log:
            logger.info(f"⏱  等待 {wait:.1f}s (type={t.value})")
        time.sleep(wait)
        return wait


# ---------- BroadcastTask ---------- #

class BroadcastTask(BaseModel):
    """一批客户 (可 1 人可 N 人) 共享一份消息序列"""

    contacts: list[str] = Field(..., min_length=1)
    messages: list[Message] = Field(..., min_length=1)
    #: 可选备注，方便 GUI 展示 (比如 "VIP 客户 · 春节问候")
    label: str | None = None

    @field_validator("contacts")
    @classmethod
    def _dedup_contacts(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for c in v:
            c = c.strip()
            if not c:
                continue
            if c in seen:
                continue
            seen.add(c)
            out.append(c)
        if not out:
            raise ValueError("contacts 至少要 1 个非空名称")
        return out


# ---------- BatchPlan (顶层) ---------- #

class PlanMeta(BaseModel):
    name: str = "untitled"
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    note: str | None = None


class BatchPlan(BaseModel):
    """
    GUI 一次编排的产物，可保存为 JSON 复用。

    - tasks: 可含多个 BroadcastTask (给不同批客户发不同内容)
    - intervals: 类型化间隔
    """

    meta: PlanMeta = Field(default_factory=PlanMeta)
    intervals: TypedIntervals = Field(default_factory=TypedIntervals)
    tasks: list[BroadcastTask] = Field(..., min_length=1)

    # ---------- 统计辅助 ---------- #

    def total_messages(self) -> int:
        return sum(len(t.messages) for t in self.tasks)

    def total_sends(self) -> int:
        """
        大致预估: 每条消息 × 目标数
        (转发类多选会合并到 1 次操作，但真正发出的份数不变)
        """
        return sum(len(t.contacts) * len(t.messages) for t in self.tasks)

    def unique_contacts(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for t in self.tasks:
            for c in t.contacts:
                if c not in seen:
                    seen.add(c)
                    out.append(c)
        return out


# ---------- JSON 存取 ---------- #

def save_plan(plan: BatchPlan, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = plan.model_dump(mode="json")
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def load_plan(path: str | Path) -> BatchPlan:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"plan 不存在: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return BatchPlan.model_validate(raw)
