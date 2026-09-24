"""
Stage 4.5.1 数据模型单元测试。

跑法:
    pytest tests/test_messaging_plan.py -v
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.messaging import (
    BatchPlan,
    BroadcastTask,
    Message,
    MessageType,
    TypedIntervals,
    DIRECT_SEND_TYPES,
    FORWARD_TYPES,
    load_plan,
    save_plan,
)


# ---------- MessageType 分类 ---------- #

def test_types_covered_exactly():
    """DIRECT + FORWARD 必须覆盖所有类型且不重叠"""
    assert DIRECT_SEND_TYPES.isdisjoint(FORWARD_TYPES)
    assert DIRECT_SEND_TYPES | FORWARD_TYPES == set(MessageType)


# ---------- Message 校验 ---------- #

def test_text_message_ok():
    m = Message.text_msg("周末愉快")
    assert m.type == MessageType.TEXT
    assert m.text == "周末愉快"

def test_text_message_needs_text():
    with pytest.raises(ValidationError):
        Message(type=MessageType.TEXT)

def test_image_needs_path():
    with pytest.raises(ValidationError):
        Message(type=MessageType.IMAGE)
    m = Message.image("C:/a.jpg", caption="c")
    assert m.path == "C:/a.jpg" and m.caption == "c"

def test_miniprogram_needs_tag():
    with pytest.raises(ValidationError):
        Message(type=MessageType.MINIPROGRAM)
    m = Message.miniprogram("mp_intro")
    assert m.tag == "mp_intro"

def test_contact_card_needs_friend():
    with pytest.raises(ValidationError):
        Message(type=MessageType.CONTACT_CARD)
    m = Message.contact_card("张三")
    assert m.friend_name == "张三"

def test_whitespace_stripped_to_none():
    """空串/纯空格应被去掉，进而触发 type 校验错误"""
    with pytest.raises(ValidationError):
        Message(type=MessageType.TEXT, text="   ")

def test_brief_no_crash():
    for m in (
        Message.text_msg("你好"),
        Message.image("a/b.jpg"),
        Message.miniprogram("mp_x"),
        Message.contact_card("张三"),
    ):
        assert isinstance(m.brief(), str)
        assert len(m.brief()) > 0


# ---------- BroadcastTask ---------- #

def test_task_contacts_deduped():
    t = BroadcastTask(
        contacts=["张三", "李四", "张三", " 王五 ", "李四"],
        messages=[Message.text_msg("hi")],
    )
    assert t.contacts == ["张三", "李四", "王五"]

def test_task_needs_at_least_one_contact():
    with pytest.raises(ValidationError):
        BroadcastTask(contacts=[], messages=[Message.text_msg("hi")])
    with pytest.raises(ValidationError):
        BroadcastTask(contacts=["  ", ""], messages=[Message.text_msg("hi")])

def test_task_needs_at_least_one_message():
    with pytest.raises(ValidationError):
        BroadcastTask(contacts=["张三"], messages=[])


# ---------- TypedIntervals ---------- #

def test_intervals_default_all_types():
    ti = TypedIntervals()
    for t in MessageType:
        lo, hi = ti.get(t)
        assert 0 <= lo <= hi

def test_intervals_reject_negative():
    with pytest.raises(ValidationError):
        TypedIntervals(text=(-1, 5))

def test_intervals_reject_reversed():
    with pytest.raises(ValidationError):
        TypedIntervals(text=(10, 3))


# ---------- BatchPlan 统计 ---------- #

def _sample_plan() -> BatchPlan:
    return BatchPlan(
        tasks=[
            BroadcastTask(
                contacts=["张三", "李四"],
                messages=[
                    Message.text_msg("hi"),
                    Message.image("a.jpg"),
                ],
            ),
            BroadcastTask(
                contacts=["群姐", "李四"],   # 李四重复出现在两个 task 是允许的
                messages=[Message.miniprogram("mp_x")],
            ),
        ]
    )

def test_plan_totals():
    p = _sample_plan()
    assert p.total_messages() == 3        # 2 + 1
    assert p.total_sends() == 2*2 + 2*1   # 6
    # 去重 (张三, 李四, 群姐)
    assert p.unique_contacts() == ["张三", "李四", "群姐"]


# ---------- JSON 序列化 ---------- #

def test_roundtrip_json(tmp_path: Path):
    p = _sample_plan()
    fp = tmp_path / "plan.json"
    save_plan(p, fp)
    loaded = load_plan(fp)
    assert loaded.total_messages() == p.total_messages()
    assert loaded.tasks[0].messages[0].text == "hi"
    assert loaded.tasks[1].messages[0].tag == "mp_x"

def test_json_utf8(tmp_path: Path):
    p = _sample_plan()
    fp = tmp_path / "plan.json"
    save_plan(p, fp)
    raw = fp.read_text(encoding="utf-8")
    # 中文必须直接可见 (ensure_ascii=False)
    assert "张三" in raw
    assert "\\u" not in raw

def test_load_sample_file():
    """项目自带样例必须能被解析"""
    sample = Path(__file__).parent.parent / "samples" / "plan_example.json"
    if not sample.exists():
        pytest.skip("样例文件不存在")
    p = load_plan(sample)
    assert len(p.tasks) >= 1
    assert p.total_sends() > 0
