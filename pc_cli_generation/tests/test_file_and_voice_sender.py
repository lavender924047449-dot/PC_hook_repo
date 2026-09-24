"""
FileSender / VoiceSender 单元测试 (mock nav).

新语义 (Stage 4.5.4 v2):
  * FileSender 不再 adb push, message.path = SAF 文件名关键字
  * 前置: 用户已手动把文件发到「文件传输助手」, 使其出现在 SAF「最近」
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from app.messaging import Message, MessageType, SendContext
from app.messaging.senders import FileSender, VoiceSender


@dataclass
class MockNav:
    events: list[tuple[str, object]] = field(default_factory=list)

    def open_plus_panel(self) -> None:
        self.events.append(("open_plus_panel", None))

    def open_file_picker(self) -> None:
        self.events.append(("open_file_picker", None))

    def choose_local_file_source(self) -> None:
        self.events.append(("choose_local_source", None))

    def pick_file_by_name(self, name: str, *, scroll_max: int = 8) -> None:
        self.events.append(("pick_file", name))

    def tap_media_send(self, *, wait_after_s: float = 1.5) -> None:
        self.events.append(("tap_media_send", wait_after_s))


# ---------- FileSender ---------- #

def test_file_sender_full_chain():
    nav = MockNav()
    ctx = SendContext(nav=nav)
    FileSender().send(ctx, ["张三"], Message.file("Pupuapp"))

    kinds = [e[0] for e in nav.events]
    assert kinds == [
        "open_plus_panel",
        "open_file_picker",
        "choose_local_source",
        "pick_file",
        "tap_media_send",
    ]
    assert nav.events[3][1] == "Pupuapp"


def test_file_sender_rejects_multi_target():
    ctx = SendContext(nav=MockNav())
    with pytest.raises(ValueError, match=r"单个"):
        FileSender().send(ctx, ["a", "b"], Message.file("kw"))


def test_file_sender_supported_type():
    assert FileSender.supported_types == frozenset({MessageType.FILE})


# ---------- VoiceSender ---------- #

def test_voice_sender_supported_type():
    assert VoiceSender.supported_types == frozenset({MessageType.VOICE})


def test_voice_sender_rejects_wrong_type():
    v = VoiceSender()
    ctx = SendContext(nav=MockNav())
    with pytest.raises(ValueError, match="VOICE"):
        v.send(ctx, ["a"], Message.text_msg("hi"))


def test_voice_sender_rejects_multi_target():
    v = VoiceSender()
    ctx = SendContext(nav=MockNav())
    with pytest.raises(ValueError, match=r"单个|targets"):
        v.send(ctx, ["a", "b"], Message.voice("x.wav"))


def test_voice_sender_needs_cfg():
    v = VoiceSender()
    ctx = SendContext(nav=MockNav(), cfg=None)
    with pytest.raises(RuntimeError, match="cfg"):
        v.send(ctx, ["a"], Message.voice("x.wav"))
