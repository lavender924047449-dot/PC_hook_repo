from app.messaging.executor import QueueExecutor
from app.messaging.send_queue import QueueItem, SendQueue
from app.pc_wecom.forward_executor import ForwardResult


class _FakeForward:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.calls: list[tuple[str, str]] = []
        self.conv_ids: list[str | None] = []

    def forward(self, code: str, target: str, *, conv_id: str | None = None, retries: int = 2):
        self.calls.append((code, target))
        self.conv_ids.append(conv_id)
        if self.ok:
            return ForwardResult(ok=True, material_code=code, target=target, conv_id=conv_id or "")
        return ForwardResult(ok=False, material_code=code, target=target, reason="mock failed")


class _FakeScheduler:
    def __init__(self) -> None:
        self.hour_checks = 0
        self.quota_checks = 0
        self.sleeps = 0
        self.records = 0

    def check_working_hours(self):
        self.hour_checks += 1

    def check_quota(self):
        self.quota_checks += 1

    def sleep_next_interval(self):
        self.sleeps += 1
        return 0.0

    def record_sent(self):
        self.records += 1


def test_executor_with_scheduler(tmp_path):
    q = SendQueue(tmp_path / "q.json")
    q.add(QueueItem(id="1", material_code="img-a", target="张三"))
    q.add(QueueItem(id="2", material_code="img-b", target="李四"))
    scheduler = _FakeScheduler()
    ex = QueueExecutor(q, _FakeForward(ok=True), history_path=tmp_path / "history.json", scheduler=scheduler)
    out = ex.run()
    assert len(out) == 2
    assert scheduler.hour_checks == 2
    assert scheduler.quota_checks == 2
    assert scheduler.records == 2
    assert scheduler.sleeps == 1


def test_executor_failed_status(tmp_path):
    q = SendQueue(tmp_path / "q.json")
    q.add(QueueItem(id="1", material_code="img-a", target="张三"))
    ex = QueueExecutor(q, _FakeForward(ok=False), history_path=tmp_path / "history.json")
    out = ex.run()
    assert out[0]["status"] == "failed"
    assert q.items()[0].status == "failed"


class _FakeResolver:
    def __init__(self, table: dict[str, str]) -> None:
        self.table = table
        self.calls: list[str] = []

    def resolve(self, name: str) -> str | None:
        self.calls.append(name)
        return self.table.get(name)


def test_executor_resolves_target_conv_id(tmp_path):
    q = SendQueue(tmp_path / "q.json")
    q.add(QueueItem(id="1", material_code="img-a", target="张三"))
    q.add(QueueItem(id="2", material_code="img-b", target="未知"))
    fake = _FakeForward(ok=True)
    resolver = _FakeResolver({"张三": "S:1688855042791155_7881300363276969"})
    ex = QueueExecutor(
        q, fake, history_path=tmp_path / "history.json", conv_resolver=resolver,
    )
    out = ex.run()
    assert len(out) == 2
    assert fake.calls == [("img-a", "张三"), ("img-b", "未知")]
    assert fake.conv_ids == ["S:1688855042791155_7881300363276969", None]
    assert resolver.calls == ["张三", "未知"]
