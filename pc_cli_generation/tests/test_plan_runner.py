"""
Stage 4.5.9 PlanRunner 单元测试.

覆盖:
    * build_steps: plan → 原子步骤序列
    * plan_hash: 稳定 hash
    * ProgressStore: load/save/clear
    * PlanRunner: 干跑 / 严格 / 宽松 / resume / limit_contacts / 报告
    * Scheduler 门控: quota 超限 → 中止
"""

from __future__ import annotations

import json

import pytest

from app.config import ScheduleConfig
from app.messaging.asset_library import AssetLibrary
from app.messaging.plan import BatchPlan, BroadcastTask, PlanMeta, TypedIntervals
from app.messaging.runner import (
    PlanRunner,
    ProgressStore,
    StepKind,
    StepStatus,
    build_steps,
    plan_hash,
)
from app.messaging.sender import SendContext, SenderRegistry
from app.messaging.types import Message, MessageType
from app.orchestrator.scheduler import Scheduler


# ======================== helpers ======================== #


def _fast_intervals() -> TypedIntervals:
    """所有类型 (0, 0) 秒, 加速测试"""
    zeros = (0.0, 0.0)
    return TypedIntervals(
        text=zeros, image=zeros, video=zeros, file=zeros, voice=zeros,
        contact_card=zeros, location=zeros, sticker=zeros,
        miniprogram=zeros, channel_video=zeros,
    )


def _fast_schedule() -> Scheduler:
    """宽松配额, 全天工作时段"""
    return Scheduler(
        ScheduleConfig(
            min_interval_s=0, max_interval_s=0,
            hourly_limit=10_000, daily_limit=10_000,
            working_hours=(0, 24),
        ),
        jitter=False,
    )


def _mini_plan(fta_locator: str = "商品A") -> tuple[BatchPlan, AssetLibrary]:
    """构造一个包含 direct+forward 的小 plan + 配套 AssetLibrary"""
    lib = AssetLibrary()
    # 用内存路径, save 时会写但测试不需要 (设 tmp 目录更好)
    entry = lib.register_forward(
        semantic_type=MessageType.MINIPROGRAM,
        fta_locator=fta_locator,
    )
    tag = entry.tag

    plan = BatchPlan(
        meta=PlanMeta(name="test_plan"),
        intervals=_fast_intervals(),
        tasks=[
            BroadcastTask(
                label="task-A",
                contacts=["张三", "李四"],
                messages=[
                    Message.text_msg("hello"),
                    Message.miniprogram(tag),
                ],
            ),
        ],
    )
    return plan, lib


# ======================== build_steps ======================== #


class TestBuildSteps:
    def test_direct_and_forward_order(self):
        plan, _ = _mini_plan()
        steps = build_steps(plan)
        # 期望顺序:
        #   direct: 张三×text, 李四×text
        #   forward: miniprogram × [张三, 李四]
        assert len(steps) == 3
        assert steps[0].kind is StepKind.DIRECT
        assert steps[0].contacts == ["张三"]
        assert steps[0].msg_type is MessageType.TEXT
        assert steps[1].kind is StepKind.DIRECT
        assert steps[1].contacts == ["李四"]
        assert steps[2].kind is StepKind.FORWARD
        assert steps[2].contacts == ["张三", "李四"]
        assert steps[2].msg_type is MessageType.MINIPROGRAM

    def test_multi_direct_msgs_per_contact(self):
        plan = BatchPlan(
            intervals=_fast_intervals(),
            tasks=[
                BroadcastTask(
                    contacts=["A"],
                    messages=[
                        Message.text_msg("m1"),
                        Message.text_msg("m2"),
                    ],
                ),
            ],
        )
        steps = build_steps(plan)
        assert [s.msg_index for s in steps] == [0, 1]

    def test_step_id_stable_and_unique(self):
        plan, _ = _mini_plan()
        steps = build_steps(plan)
        ids = [s.step_id for s in steps]
        assert len(set(ids)) == len(ids)  # 唯一
        # 再来一遍应该相同 (稳定)
        steps2 = build_steps(plan)
        assert [s.step_id for s in steps2] == ids


# ======================== plan_hash ======================== #


class TestPlanHash:
    def test_stable_across_calls(self):
        plan, _ = _mini_plan()
        assert plan_hash(plan) == plan_hash(plan)

    def test_different_plans_different_hash(self):
        p1, _ = _mini_plan("商品A")
        p2, _ = _mini_plan("商品B")
        assert plan_hash(p1) != plan_hash(p2)


# ======================== ProgressStore ======================== #


class TestProgressStore:
    def test_missing_file_returns_none(self, tmp_path):
        store = ProgressStore("abc123", base_dir=tmp_path)
        assert store.load() is None

    def test_save_and_reload(self, tmp_path):
        from app.messaging.runner import ProgressState
        store = ProgressStore("abc123", base_dir=tmp_path)
        st = ProgressState(plan_hash="abc123")
        st.completed_step_ids = ["s1", "s2"]
        store.save(st)
        got = store.load()
        assert got is not None
        assert got.completed_step_ids == ["s1", "s2"]
        assert got.updated_at  # 应被填充

    def test_mismatched_hash_ignored(self, tmp_path):
        # 写一个 hash=X 的文件, 读时按 Y 加载 → 返回 None
        p = tmp_path / "plan_Y.json"
        p.write_text(json.dumps({
            "plan_hash": "X", "completed_step_ids": [],
            "failed_step_ids": [], "started_at": "", "updated_at": "",
        }), encoding="utf-8")
        # ProgressStore 期望文件名与 hash 一致; 这里手工放不同 hash
        store = ProgressStore("Y", base_dir=tmp_path)
        assert store.load() is None

    def test_clear(self, tmp_path):
        from app.messaging.runner import ProgressState
        store = ProgressStore("abc123", base_dir=tmp_path)
        store.save(ProgressState(plan_hash="abc123"))
        assert store.path.exists()
        store.clear()
        assert not store.path.exists()


# ======================== PlanRunner (dry-run) ======================== #


class _MockSender:
    """通用 mock sender, 记录调用. supported_types 传入构造."""
    def __init__(self, types: set[MessageType]):
        self.supported_types = frozenset(types)
        self.calls: list[tuple[list[str], MessageType]] = []
        self.raise_on_type: MessageType | None = None
        self.raise_on_contact: str | None = None

    def send(self, ctx, targets, message):
        self.calls.append((list(targets), message.type))
        if (self.raise_on_type == message.type
                or self.raise_on_contact in targets):
            raise RuntimeError(f"mock failure on {message.type.value}/{targets}")


@pytest.fixture
def registry_all_mock():
    """注册覆盖 TEXT + MINIPROGRAM 的 mock sender"""
    reg = SenderRegistry()
    text_s = _MockSender({MessageType.TEXT})
    fwd_s = _MockSender({MessageType.MINIPROGRAM,
                          MessageType.CHANNEL_VIDEO,
                          MessageType.LOCATION})
    reg.register(text_s)
    reg.register(fwd_s)
    return reg, text_s, fwd_s


@pytest.fixture
def make_runner(tmp_path):
    """工厂: 返回 (runner, plan, lib, text_sender, fwd_sender)"""
    def _make(**overrides):
        plan, lib = _mini_plan()
        reg = SenderRegistry()
        text_s = _MockSender({MessageType.TEXT})
        fwd_s = _MockSender({MessageType.MINIPROGRAM,
                              MessageType.CHANNEL_VIDEO,
                              MessageType.LOCATION})
        reg.register(text_s)
        reg.register(fwd_s)

        ctx = SendContext(nav=None, asset_library=lib)
        kwargs = dict(
            plan=plan, registry=reg, ctx=ctx,
            scheduler=_fast_schedule(),
            strict=True, jitter=False,
            progress_dir=tmp_path / "progress",
            report_dir=tmp_path / "reports",
        )
        kwargs.update(overrides)
        runner = PlanRunner(**kwargs)
        return runner, plan, lib, text_s, fwd_s
    return _make


class TestPlanRunnerDryRun:
    def test_dry_run_no_send_calls(self, make_runner):
        runner, plan, lib, text_s, fwd_s = make_runner(dry_run=True)
        results = runner.run()
        # 所有 step 应标 SENT (dry-run 视为成功)
        assert all(s.status is StepStatus.SENT for s in results)
        # sender 不应被调用
        assert text_s.calls == []
        assert fwd_s.calls == []

    def test_writes_reports(self, make_runner, tmp_path):
        runner, *_ = make_runner(dry_run=True)
        runner.run()
        report_files = list((tmp_path / "reports").glob("plan_*.json"))
        assert len(report_files) == 1
        payload = json.loads(report_files[0].read_text(encoding="utf-8"))
        assert payload["plan_name"] == "test_plan"
        assert payload["counts"].get("sent") == 3
        # CSV 也应存在
        csv_files = list((tmp_path / "reports").glob("plan_*.csv"))
        assert len(csv_files) == 1


# ======================== PlanRunner (真跑, mock sender) ======================== #


class TestPlanRunnerReal:
    def test_all_success(self, make_runner):
        runner, plan, lib, text_s, fwd_s = make_runner()
        results = runner.run()
        assert all(s.status is StepStatus.SENT for s in results)
        # text: 2 次 (每人一次); forward: 1 次 (两人打包)
        assert len(text_s.calls) == 2
        assert len(fwd_s.calls) == 1
        assert fwd_s.calls[0][0] == ["张三", "李四"]

    def test_strict_stops_on_failure(self, make_runner):
        runner, plan, lib, text_s, fwd_s = make_runner(strict=True)
        text_s.raise_on_contact = "张三"  # 第一步就失败
        results = runner.run()
        # 张三 FAILED, 其余全部 SKIPPED
        statuses = [s.status for s in results]
        assert statuses[0] is StepStatus.FAILED
        assert all(s is StepStatus.SKIPPED for s in statuses[1:])

    def test_loose_continues_on_failure(self, make_runner):
        runner, plan, lib, text_s, fwd_s = make_runner(strict=False)
        text_s.raise_on_contact = "张三"
        results = runner.run()
        statuses = [s.status for s in results]
        # 张三 failed, 李四/forward 应继续 sent
        assert statuses[0] is StepStatus.FAILED
        assert statuses[1] is StepStatus.SENT
        assert statuses[2] is StepStatus.SENT

    def test_stop_requested_skips_rest(self, make_runner):
        state = {"n": 0}

        def should_stop() -> bool:
            state["n"] += 1
            # 第 1 步之后尽快停
            return state["n"] > 2

        runner, *_ = make_runner(should_stop=should_stop)
        results = runner.run()
        assert results[0].status in (StepStatus.SENT, StepStatus.RUNNING)
        assert results[1].status is StepStatus.SKIPPED
        assert results[2].status is StepStatus.SKIPPED
        assert "stopped by user" in (results[1].error or "")


class TestLimitContacts:
    def test_limit_1_reduces_steps(self, make_runner):
        runner, plan, lib, text_s, fwd_s = make_runner(limit_contacts=1)
        results = runner.run()
        # 应为 1 direct + 1 forward = 2 step
        assert len(results) == 2
        assert results[0].contacts == ["张三"]
        assert results[1].contacts == ["张三"]


# ======================== Resume ======================== #


class TestResume:
    def test_resume_skips_completed(self, make_runner, tmp_path):
        # 第一次跑: 让第一步失败 (loose 模式), 保留进度
        r1, *_ = make_runner(strict=False)
        r1.registry.get(MessageType.TEXT).raise_on_contact = "李四"
        r1.run()
        prog_file = list((tmp_path / "progress").glob("plan_*.json"))
        assert len(prog_file) == 1
        state = json.loads(prog_file[0].read_text(encoding="utf-8"))
        assert len(state["completed_step_ids"]) == 2  # 张三 + forward
        assert len(state["failed_step_ids"]) == 1     # 李四

    def test_resume_reads_progress(self, make_runner):
        # 第一次跑 loose, 李四失败
        r1, *_ = make_runner(strict=False)
        r1.registry.get(MessageType.TEXT).raise_on_contact = "李四"
        r1.run()

        # 第二次 resume (让李四这次通过)
        r2, *_ = make_runner(strict=True, resume=True)
        # 不再 raise
        results = r2.run()
        text_s = r2.registry.get(MessageType.TEXT)
        # 只有李四这一步该被真跑
        assert len(text_s.calls) == 1
        assert text_s.calls[0][0] == ["李四"]


# ======================== Scheduler 门控 ======================== #


class TestSchedulerGating:
    def test_quota_exceeded_aborts(self, make_runner):
        sch = Scheduler(
            ScheduleConfig(
                min_interval_s=0, max_interval_s=0,
                hourly_limit=1, daily_limit=100,   # 1h 限制 1 条
                working_hours=(0, 24),
            ),
            jitter=False,
        )
        runner, *_ = make_runner(scheduler=sch)
        results = runner.run()
        # 第 1 步 SENT, 第 2 步 check_quota 应拒绝 → 剩余 SKIPPED
        assert results[0].status is StepStatus.SENT
        assert results[1].status is StepStatus.SKIPPED
        assert results[2].status is StepStatus.SKIPPED
        # error 应带 "上限" 字样
        assert "上限" in (results[1].error or "")

    def test_outside_working_hours_aborts(self, make_runner):
        # 工作时段设成一个不可能命中的窗口 (start==end)
        sch = Scheduler(
            ScheduleConfig(
                min_interval_s=0, max_interval_s=0,
                hourly_limit=10, daily_limit=10,
                working_hours=(3, 3),  # 空窗口, 永不通过
            ),
            jitter=False,
        )
        runner, *_ = make_runner(scheduler=sch)
        results = runner.run()
        # 首步就应被 SKIPPED (从未 SENT)
        assert all(s.status is StepStatus.SKIPPED for s in results)
        assert "工作时段" in (results[0].error or "")

    def test_dry_run_ignores_working_hours(self, make_runner):
        """dry-run 应跳过风控门控, 否则下班后无法预览 plan"""
        sch = Scheduler(
            ScheduleConfig(
                min_interval_s=0, max_interval_s=0,
                hourly_limit=10, daily_limit=10,
                working_hours=(3, 3),
            ),
            jitter=False,
        )
        runner, _, _, text_s, fwd_s = make_runner(scheduler=sch, dry_run=True)
        results = runner.run()
        assert all(s.status is StepStatus.SENT for s in results)
        assert text_s.calls == []
        assert fwd_s.calls == []

    def test_ignore_schedule_allows_real_run_off_hours(self, make_runner):
        sch = Scheduler(
            ScheduleConfig(
                min_interval_s=0, max_interval_s=0,
                hourly_limit=10, daily_limit=10,
                working_hours=(3, 3),
            ),
            jitter=False,
        )
        runner, _, _, text_s, fwd_s = make_runner(
            scheduler=sch, ignore_schedule=True
        )
        results = runner.run()
        assert all(s.status is StepStatus.SENT for s in results)
        assert len(text_s.calls) == 2
        assert len(fwd_s.calls) == 1

    def test_dry_run_does_not_write_progress(self, make_runner, tmp_path):
        """dry-run 不得污染 resume 进度文件"""
        runner, *_ = make_runner(dry_run=True)
        runner.run()
        prog_files = list((tmp_path / "progress").glob("plan_*.json"))
        assert prog_files == []
