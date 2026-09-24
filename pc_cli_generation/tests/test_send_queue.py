from app.messaging.send_queue import QueueItem, SendQueue


def test_queue_add_and_reload(tmp_path):
    q = SendQueue(tmp_path / "q.json")
    q.add(QueueItem(id="1", material_code="voice-abc", target="张三"))
    assert len(q.items()) == 1

    q2 = SendQueue(tmp_path / "q.json")
    assert q2.items()[0].material_code == "voice-abc"


def test_update_status(tmp_path):
    q = SendQueue(tmp_path / "q.json")
    q.add(QueueItem(id="1", material_code="img-aaa", target="李四"))
    q.update_status("1", "failed", error="mock error")
    item = q.items()[0]
    assert item.status == "failed"
    assert item.error == "mock error"
