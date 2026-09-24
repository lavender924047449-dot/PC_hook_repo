"""
TextSender 单元测试 (无需真机, 用 mock Navigator).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from app.messaging import Message, MessageType, SendContext
from app.messaging.senders import TextSender


@dataclass
class MockNav:
    events: list[tuple[str, object]] = field(default_factory=list)
    fail_on: str | None = None

    def enter_text_mode(self) -> None:
        if self.fail_on == "enter":
            raise RuntimeError("enter_text_mode failed")
        self.events.append(("enter_text_mode", None))

    def type_text(self, text: str, *, clear: bool = True) -> None:
        if self.fail_on == "type":
            raise RuntimeError("type_text failed")
        self.events.append(("type_text", (text, clear)))

    def tap_send_button(self, *, wait_after_s: float = 1.0,
                        dump_dir=None) -> None:
        if self.fail_on == "send":
            raise RuntimeError("send failed")
        self.events.append(("tap_send_button", wait_after_s))


def test_text_sender_happy_path():
    nav = MockNav()
    sender = TextSender()
    ctx = SendContext(nav=nav)
    sender.send(ctx, ["张三"], Message.text_msg("你好，周一愉快 🌞"))

    kinds = [e[0] for e in nav.events]
    assert kinds == ["enter_text_mode", "type_text", "tap_send_button"]

    typed_text, clear = nav.events[1][1]
    assert typed_text == "你好，周一愉快 🌞"
    assert clear is True


def test_text_sender_rejects_wrong_type():
    sender = TextSender()
    ctx = SendContext(nav=MockNav())
    with pytest.raises(ValueError, match="TEXT"):
        sender.send(ctx, ["张三"], Message.image("a.jpg"))


def test_text_sender_rejects_multi_target():
    sender = TextSender()
    ctx = SendContext(nav=MockNav())
    with pytest.raises(ValueError, match="targets"):
        sender.send(ctx, ["张三", "李四"], Message.text_msg("hi"))


def test_text_sender_needs_nav():
    sender = TextSender()
    ctx = SendContext(nav=None)
    with pytest.raises(RuntimeError, match="nav"):
        sender.send(ctx, ["张三"], Message.text_msg("hi"))


def test_text_sender_supported_types():
    assert TextSender.supported_types == frozenset({MessageType.TEXT})


def test_text_sender_propagates_nav_errors():
    sender = TextSender()
    nav = MockNav(fail_on="send")
    with pytest.raises(RuntimeError, match="send failed"):
        sender.send(SendContext(nav=nav), ["张三"],
                    Message.text_msg("hi"))
