"""
Image/VideoSender 单元测试 (无需真机, mock nav + store).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from app.messaging import Message, MessageType, SendContext
from app.messaging.senders import ImageSender, VideoSender


@dataclass
class MockNav:
    events: list[tuple[str, object]] = field(default_factory=list)

    def open_plus_panel(self) -> None:
        self.events.append(("open_plus_panel", None))

    def open_gallery(self) -> None:
        self.events.append(("open_gallery", None))

    def pick_latest_in_gallery(
        self, *, prefer_name_substring: str | None = None
    ) -> None:
        self.events.append(("pick_latest", prefer_name_substring))

    def tap_media_send(self, *, wait_after_s: float = 1.5) -> None:
        self.events.append(("tap_media_send", wait_after_s))


@dataclass
class MockStore:
    pushed: list[Path] = field(default_factory=list)

    def ensure(self, local: Path | str) -> str:
        p = Path(local)
        self.pushed.append(p)
        return f"/sdcard/Pictures/wecom_batch/wb_ab1234_{p.name}"


def test_image_sender_full_chain(tmp_path: Path):
    fp = tmp_path / "hello.jpg"
    fp.write_bytes(b"\x00" * 10)
    nav, store = MockNav(), MockStore()
    ctx = SendContext(nav=nav, asset_library=store)
    ImageSender().send(ctx, ["张三"], Message.image(str(fp)))

    kinds = [e[0] for e in nav.events]
    assert kinds == ["open_plus_panel", "open_gallery",
                     "pick_latest", "tap_media_send"]
    assert store.pushed == [fp.resolve()]
    # 相册匹配用的是 remote 文件名 (含 wb_ 前缀)
    hint = nav.events[2][1]
    assert hint is not None and "hello.jpg" in hint


def test_video_sender_full_chain(tmp_path: Path):
    fp = tmp_path / "clip.mp4"
    fp.write_bytes(b"\x00" * 10)
    nav, store = MockNav(), MockStore()
    ctx = SendContext(nav=nav, asset_library=store)
    VideoSender().send(ctx, ["李四"], Message.video(str(fp)))
    kinds = [e[0] for e in nav.events]
    assert kinds == ["open_plus_panel", "open_gallery",
                     "pick_latest", "tap_media_send"]


def test_image_rejects_wrong_type(tmp_path: Path):
    ctx = SendContext(nav=MockNav(), asset_library=MockStore())
    with pytest.raises(ValueError):
        ImageSender().send(ctx, ["a"], Message.text_msg("hi"))


def test_image_rejects_missing_file(tmp_path: Path):
    ctx = SendContext(nav=MockNav(), asset_library=MockStore())
    m = Message.image(str(tmp_path / "not_here.jpg"))
    with pytest.raises(FileNotFoundError):
        ImageSender().send(ctx, ["a"], m)


def test_image_rejects_multi_target(tmp_path: Path):
    fp = tmp_path / "x.jpg"
    fp.write_bytes(b"0")
    ctx = SendContext(nav=MockNav(), asset_library=MockStore())
    with pytest.raises(ValueError, match=r"单个|targets"):
        ImageSender().send(ctx, ["a", "b"], Message.image(str(fp)))


def test_supported_types_disjoint():
    assert ImageSender.supported_types == frozenset({MessageType.IMAGE})
    assert VideoSender.supported_types == frozenset({MessageType.VIDEO})
    assert ImageSender.supported_types.isdisjoint(VideoSender.supported_types)
