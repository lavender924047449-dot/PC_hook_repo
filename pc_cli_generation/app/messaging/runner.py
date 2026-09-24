"""
PlanRunner (Stage 4.5.9) — BatchPlan 的完整执行引擎.

DEPRECATED: 此执行引擎依赖 Android 导航发送，已进入兼容维护阶段。

功能:
    * 拆分 plan 为原子 PlanStep 序列 (contact-major direct + task-level forward)
    * 每步前用 Scheduler 检查 working_hours + quota (风控门控)
    * 每步用 plan.intervals 按 MessageType 抽间隔 (type-aware spacing)
    * 严格 / 宽松模式:
        - strict: 首个失败即中止, 剩余步骤标 SKIPPED
        - loose:  记录失败继续, 最后汇总
    * 进度持久化到 runtime/progress/plan_<hash>.json  (--resume 恢复)
    * 报告落 runtime/reports/plan_<ts>.{json,csv}
    * 干跑 (dry_run) 只解析 + 打印, 不真调用 sender, 也不走风控门控 / 不写进度
    * ignore_schedule: 跳过 working_hours + quota 门控 (调试用, 真发也可开)

设计
====
* 与老 orchestrator/BatchRunner (纯语音, contact-only) 并行存在, 各司其职.
  老 BatchRunner 走 CSV → SendTask 路径; PlanRunner 走 JSON Plan → 多类型消息.
* Scheduler 只用于"门控 + 全局计数", 不再调用 sleep_next_interval;
  节奏交给 TypedIntervals (每类型独立 min/max).
* PlanStep 是纯数据 (无引用 nav/sender), 便于 JSON 序列化到进度文件.
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from loguru import logger

from app.config import resolve_path
from app.messaging.plan import BatchPlan
from app.messaging.sender import SendContext, SenderRegistry
from app.messaging.types import (
    DIRECT_SEND_TYPES,
    FORWARD_TYPES,
    Message,
    MessageType,
)
from app.orchestrator.scheduler import (
    OutsideWorkingHours,
    QuotaExceeded,
    Scheduler,
)


# ============================================================ #
#                        PlanStep                              #
# ============================================================ #


class StepKind(str, Enum):
    DIRECT = "direct"
    FORWARD = "forward"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlanStep:
    """
    一个原子发送单元.

    - kind=direct  : 一条 direct-type 消息 → 一个联系人
    - kind=forward : 一条 forward-type 消息 → 一批联系人 (走多选/单选循环由
                     ForwardSender 内部决定)
    """
    kind: StepKind
    task_index: int                     # 0-based
    msg_index: int                      # 0-based (在 task.messages 内)
    contacts: list[str]                 # direct: [1 人]; forward: [N 人]
    msg_type: MessageType
    #: 步骤稳定标识 (用于进度对齐/去重)
    step_id: str = ""

    # 运行时状态
    status: StepStatus = StepStatus.PENDING
    error: str | None = None
    attempts: int = 0
    started_at: str | None = None
    finished_at: str | None = None

    def __post_init__(self) -> None:
        if not self.step_id:
            self.step_id = self._make_id()

    def _make_id(self) -> str:
        # 稳定 id: 便于跨 run 匹配 (contacts 顺序敏感)
        contact_key = "|".join(self.contacts)
        return f"{self.kind.value}:{self.task_index}:{self.msg_index}:{contact_key}"

    def to_report_row(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "kind": self.kind.value,
            "task_index": self.task_index,
            "msg_index": self.msg_index,
            "msg_type": self.msg_type.value,
            "contacts": ",".join(self.contacts),
            "status": self.status.value,
            "attempts": self.attempts,
            "started_at": self.started_at or "",
            "finished_at": self.finished_at or "",
            "error": self.error or "",
        }


# ============================================================ #
#                     Step 枚举 (plan → steps)                  #
# ============================================================ #


def build_steps(plan: BatchPlan) -> list[PlanStep]:
    """
    把 plan 平铺成原子 PlanStep 序列.

    顺序对齐 cmd_plan_run:
      For each task:
        # Direct 阶段: contact-major (每人依次发所有 direct 消息)
        for contact in task.contacts:
          for msg_idx, m in enumerate(task.messages):
            if m.type in DIRECT_SEND_TYPES:
              yield PlanStep(direct, ..., [contact])
        # Forward 阶段: 每个 forward 消息一步, 打包 task.contacts 全部
        for msg_idx, m in enumerate(task.messages):
          if m.type in FORWARD_TYPES:
            yield PlanStep(forward, ..., task.contacts)
    """
    steps: list[PlanStep] = []
    for ti, task in enumerate(plan.tasks):
        # Direct 阶段
        for contact in task.contacts:
            for mi, msg in enumerate(task.messages):
                if msg.type in DIRECT_SEND_TYPES:
                    steps.append(PlanStep(
                        kind=StepKind.DIRECT,
                        task_index=ti,
                        msg_index=mi,
                        contacts=[contact],
                        msg_type=msg.type,
                    ))
        # Forward 阶段 (每消息一步, 全部 contacts)
        for mi, msg in enumerate(task.messages):
            if msg.type in FORWARD_TYPES:
                steps.append(PlanStep(
                    kind=StepKind.FORWARD,
                    task_index=ti,
                    msg_index=mi,
                    contacts=list(task.contacts),
                    msg_type=msg.type,
                ))
    return steps


# ============================================================ #
#                     进度持久化                                #
# ============================================================ #


def plan_hash(plan: BatchPlan) -> str:
    """基于 plan 结构计算稳定 hash, 用于关联进度文件"""
    fingerprint = {
        "meta_name": plan.meta.name,
        "tasks": [
            {
                "label": t.label,
                "contacts": t.contacts,
                "messages": [m.model_dump(mode="json") for m in t.messages],
            }
            for t in plan.tasks
        ],
    }
    raw = json.dumps(fingerprint, ensure_ascii=False, sort_keys=True)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


@dataclass
class ProgressState:
    """
    进度快照 (存 JSON):
      completed_step_ids: 已成功发送 (SENT) 的 step_id 集合
      failed_step_ids:    已明确失败 (FAILED) 的 step_id 集合 (loose 模式产生)
    """
    plan_hash: str
    started_at: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )
    updated_at: str = ""
    completed_step_ids: list[str] = field(default_factory=list)
    failed_step_ids: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ProgressState":
        return cls(
            plan_hash=data["plan_hash"],
            started_at=data.get("started_at", ""),
            updated_at=data.get("updated_at", ""),
            completed_step_ids=list(data.get("completed_step_ids", [])),
            failed_step_ids=list(data.get("failed_step_ids", [])),
        )


class ProgressStore:
    """
    进度文件读写. 默认路径 runtime/progress/plan_<hash>.json.
    """

    def __init__(
        self,
        plan_hash_str: str,
        base_dir: Path | str = "runtime/progress",
    ) -> None:
        self.plan_hash = plan_hash_str
        self.path: Path = resolve_path(base_dir) / f"plan_{plan_hash_str}.json"

    def load(self) -> ProgressState | None:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            st = ProgressState.from_json(data)
            if st.plan_hash != self.plan_hash:
                logger.warning(
                    f"进度文件 plan_hash 不匹配 (读到={st.plan_hash}, "
                    f"当前={self.plan_hash}), 忽略"
                )
                return None
            return st
        except Exception as e:
            logger.warning(f"进度文件损坏 ({self.path.name}): {e}; 忽略")
            return None

    def save(self, state: ProgressState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        state.updated_at = datetime.now().isoformat(timespec="seconds")
        self.path.write_text(
            json.dumps(state.to_json(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()


# ============================================================ #
#                        Callbacks                             #
# ============================================================ #


ProgressCallback = Callable[[PlanStep, int, int], None]
StopCheck = Callable[[], bool]


# ============================================================ #
#                        PlanRunner                            #
# ============================================================ #


class PlanRunner:
    def __init__(
        self,
        plan: BatchPlan,
        registry: SenderRegistry,
        ctx: SendContext,
        scheduler: Scheduler,
        *,
        strict: bool = True,
        jitter: bool = True,
        dry_run: bool = False,
        ignore_schedule: bool = False,
        resume: bool = False,
        limit_contacts: int = 0,
        progress_dir: Path | str = "runtime/progress",
        report_dir: Path | str = "runtime/reports",
        progress_cb: ProgressCallback | None = None,
        should_stop: StopCheck | None = None,
    ) -> None:
        self.plan = plan
        self.registry = registry
        self.ctx = ctx
        self.scheduler = scheduler
        self.strict = strict
        self.jitter = jitter
        self.dry_run = dry_run
        self.ignore_schedule = ignore_schedule or dry_run
        self.resume = resume
        self.limit_contacts = limit_contacts
        self.progress_cb = progress_cb
        self.should_stop = should_stop

        self.plan_hash = plan_hash(plan)
        self.progress_store = ProgressStore(self.plan_hash, progress_dir)
        self.report_dir = resolve_path(report_dir)
        self.last_report_paths: list[Path] = []

        # 应用 limit_contacts (调试用: 每个 task 只跑前 N 人)
        if self.limit_contacts > 0:
            self._apply_limit_contacts()

        self.steps: list[PlanStep] = build_steps(plan)

    # ------------------------------------------------------ #

    def _apply_limit_contacts(self) -> None:
        """按 limit_contacts 截断每个 task.contacts (不修改原 plan 对象引用)"""
        for t in self.plan.tasks:
            t.contacts[:] = t.contacts[:self.limit_contacts]

    # ------------------------------------------------------ #

    def run(self) -> list[PlanStep]:
        n = len(self.steps)
        logger.info(
            f"── PlanRunner 启动: {self.plan.meta.name} ──"
        )
        logger.info(
            f"   plan_hash={self.plan_hash}  steps={n}  "
            f"strict={self.strict}  dry_run={self.dry_run}  "
            f"ignore_schedule={self.ignore_schedule}  resume={self.resume}"
        )

        # ---- 加载进度 (resume) ---- #
        state = self._init_state()
        completed = set(state.completed_step_ids)
        failed_prior = set(state.failed_step_ids)

        if self.resume and (completed or failed_prior):
            logger.info(
                f"   resume: 跳过 {len(completed)} 已完成, "
                f"重试 {len(failed_prior)} 之前失败"
            )

        # ---- 主循环 ---- #
        aborted = False
        for i, step in enumerate(self.steps):
            if self._stop_requested():
                logger.warning("收到停止请求，结束剩余步骤")
                self._skip_rest(i, "stopped by user")
                aborted = True
                break

            # 跳过已完成
            if self.resume and step.step_id in completed:
                step.status = StepStatus.SENT
                self._notify(step, i + 1, n)
                continue

            # ---- 前置门控 (dry-run / --ignore-schedule 跳过) ---- #
            if not self.ignore_schedule:
                try:
                    self.scheduler.check_working_hours()
                    self.scheduler.check_quota()
                except (OutsideWorkingHours, QuotaExceeded) as e:
                    logger.error(f"停止批处理: {e}")
                    self._skip_rest(i, str(e))
                    aborted = True
                    break

            # ---- 间隔 (type-aware) ---- #
            if not self.dry_run and i > 0:
                wait = self.plan.intervals.pick(step.msg_type, jitter=self.jitter)
                logger.info(
                    f"  ⏱  wait {wait:.1f}s (type={step.msg_type.value})"
                )
                if not self._sleep_interruptible(wait):
                    logger.warning("等待阶段收到停止请求，结束剩余步骤")
                    self._skip_rest(i, "stopped by user")
                    aborted = True
                    break

            # ---- 执行 ---- #
            step.started_at = datetime.now().isoformat(timespec="seconds")
            step.status = StepStatus.RUNNING
            step.attempts += 1
            self._notify(step, i + 1, n)

            try:
                self._run_step(step)
                step.status = StepStatus.SENT
                step.finished_at = datetime.now().isoformat(timespec="seconds")
                if not self.dry_run:
                    self.scheduler.record_sent()
                stats = self.scheduler.stats()
                logger.info(
                    f"  [{i + 1}/{n}] ✓ {step.kind.value} "
                    f"task#{step.task_index} msg#{step.msg_index} "
                    f"({step.msg_type.value}) → {step.contacts}  "
                    f"1h={stats['sent_last_hour']} 24h={stats['sent_last_24h']}"
                )
                completed.add(step.step_id)
                # incremental persist
                state.completed_step_ids = sorted(completed)
                state.failed_step_ids = [
                    sid for sid in state.failed_step_ids if sid not in completed
                ]
                if not self.dry_run:
                    self.progress_store.save(state)

            except Exception as e:
                step.status = StepStatus.FAILED
                step.error = str(e)
                step.finished_at = datetime.now().isoformat(timespec="seconds")
                logger.exception(
                    f"  [{i + 1}/{n}] ✗ {step.kind.value} "
                    f"task#{step.task_index} msg#{step.msg_index}: {e}"
                )
                # 记入进度 (loose 模式下, 便于日后 resume 只重跑 failed)
                if step.step_id not in state.failed_step_ids:
                    state.failed_step_ids.append(step.step_id)
                if not self.dry_run:
                    self.progress_store.save(state)
                self._notify(step, i + 1, n)

                if self.strict:
                    logger.error("严格模式: 首个失败即停")
                    self._skip_rest(i + 1, "aborted by previous failure")
                    aborted = True
                    break
                # loose: continue

            self._notify(step, i + 1, n)

        # ---- 报告 ---- #
        report_paths = self._write_reports()
        self.last_report_paths = report_paths
        for p in report_paths:
            logger.info(f"报告: {p}")
        self._print_summary(aborted)
        return self.steps

    # ------------------------------------------------------ #

    def _run_step(self, step: PlanStep) -> None:
        """执行一个 step: 定位 sender + 打开 chat (direct) + sender.send"""
        if self.dry_run:
            logger.info(
                f"  [dry-run] would send: {step.kind.value} "
                f"task#{step.task_index} msg#{step.msg_index} "
                f"→ {step.contacts}"
            )
            return

        msg: Message = self.plan.tasks[step.task_index].messages[step.msg_index]
        sender = self.registry.get(step.msg_type)
        nav = self.ctx.nav

        if step.kind is StepKind.DIRECT:
            contact = step.contacts[0]
            if nav is not None:
                # DIRECT 类需先打开聊天. 由 Runner 承担 (对齐 cmd_plan_run 旧逻辑)
                logger.debug(f"  ▶ 打开聊天: {contact}")
                nav.goto_home()
                nav.open_chat(contact)
            sender.send(self.ctx, [contact], msg)
        else:  # FORWARD
            # ForwardSender 内部处理 open_fta + 多选/单选
            sender.send(self.ctx, list(step.contacts), msg)

    # ------------------------------------------------------ #

    def _init_state(self) -> ProgressState:
        if self.resume:
            existing = self.progress_store.load()
            if existing is not None:
                return existing
        # 新建
        return ProgressState(plan_hash=self.plan_hash)

    def _skip_rest(self, from_idx: int, reason: str) -> None:
        for rest in self.steps[from_idx:]:
            if rest.status == StepStatus.PENDING:
                rest.status = StepStatus.SKIPPED
                rest.error = reason

    def _notify(self, step: PlanStep, idx: int, total: int) -> None:
        if self.progress_cb:
            try:
                self.progress_cb(step, idx, total)
            except Exception as e:
                logger.debug(f"progress_cb 抛异常, 忽略: {e}")

    def _stop_requested(self) -> bool:
        if self.should_stop is None:
            return False
        try:
            return bool(self.should_stop())
        except Exception as e:
            logger.debug(f"should_stop 检查异常，按不停处理: {e}")
            return False

    def _sleep_interruptible(self, sec: float) -> bool:
        """可中断 sleep: 收到停止请求时返回 False。"""
        if sec <= 0:
            return not self._stop_requested()
        import time as _time
        left = float(sec)
        while left > 0:
            if self._stop_requested():
                return False
            span = 0.2 if left > 0.2 else left
            _time.sleep(span)
            left -= span
        return not self._stop_requested()

    # ------------------------------------------------------ #

    def _write_reports(self) -> list[Path]:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = f"plan_{self.plan_hash}_{ts}"

        json_path = self.report_dir / f"{stem}.json"
        csv_path = self.report_dir / f"{stem}.csv"

        # JSON
        summary_counts: dict[str, int] = {}
        for s in self.steps:
            summary_counts[s.status.value] = (
                summary_counts.get(s.status.value, 0) + 1
            )
        payload = {
            "plan_name": self.plan.meta.name,
            "plan_hash": self.plan_hash,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "strict": self.strict,
            "dry_run": self.dry_run,
            "counts": summary_counts,
            "steps": [s.to_report_row() for s in self.steps],
        }
        json_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        # CSV
        rows = [s.to_report_row() for s in self.steps]
        if rows:
            with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
        return [json_path, csv_path]

    def _print_summary(self, aborted: bool) -> None:
        counts: dict[str, int] = {}
        for s in self.steps:
            counts[s.status.value] = counts.get(s.status.value, 0) + 1
        parts = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        prefix = "🟡 中止" if aborted else "🟢 完成"
        logger.info(f"{prefix}  {parts}")
