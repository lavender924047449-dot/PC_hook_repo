"""
Stage 4.5.8 StickerSender 单元测试.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.messaging.asset_library import AssetEntry, AssetLibrary
from app.messaging.sender import SendContext, SenderRegistry, is_forward_sender
from app.messaging.senders.sticker import StickerSender
from app.messaging.types import DIRECT_SEND_TYPES, Message, MessageType


@pytest.fixture
def lib(tmp_path):
    return AssetLibrary(tmp_path / "asset_library.json")


@pytest.fixture
def stk_tag(lib):
    entry = lib.register_forward(
        semantic_type=MessageType.STICKER,
        fta_locator="idx:0",
        display_name="猫咪表情",
    )
    return entry.tag


@pytest.fixture
def mock_nav():
    return MagicMock()


@pytest.fixture
def mock_cfg():
    cfg = MagicMock()
    cfg.timing.after_send_wait_s = 1.2
    return cfg


@pytest.fixture
def ctx(mock_nav, mock_cfg, lib):
    return SendContext(nav=mock_nav, cfg=mock_cfg, asset_library=lib)


@pytest.fixture
def sender():
    return StickerSender()


# ================== 契约 ================== #


class TestContract:
    def test_supported_only_sticker(self, sender):
        assert sender.supported_types == frozenset({MessageType.STICKER})

    def test_is_direct_sender(self, sender):
        assert not is_forward_sender(sender)
        assert MessageType.STICKER in DIRECT_SEND_TYPES

    def test_registrable(self, sender):
        reg = SenderRegistry()
        reg.register(sender)
        assert MessageType.STICKER in reg


# ================== 校验 ================== #


class TestValidation:
    def test_reject_wrong_type(self, sender, ctx):
        msg = Message.text_msg("hi")
        with pytest.raises(ValueError, match="只接收 STICKER"):
            sender.send(ctx, ["张三"], msg)

    def test_reject_multi_targets(self, sender, ctx, stk_tag):
        msg = Message.sticker(stk_tag)
        with pytest.raises(ValueError, match="只发单个联系人"):
            sender.send(ctx, ["A", "B"], msg)

    def test_reject_empty_tag(self, sender, ctx):
        msg = Message.model_construct(type=MessageType.STICKER, tag=None)
        with pytest.raises(ValueError, match="tag"):
            sender.send(ctx, ["A"], msg)

    def test_reject_missing_nav(self, mock_cfg, lib, stk_tag):
        ctx = SendContext(nav=None, cfg=mock_cfg, asset_library=lib)
        msg = Message.sticker(stk_tag)
        with pytest.raises(RuntimeError, match="nav"):
            StickerSender().send(ctx, ["A"], msg)

    def test_reject_missing_asset_library(self, mock_nav, mock_cfg):
        ctx = SendContext(nav=mock_nav, cfg=mock_cfg, asset_library=None)
        msg = Message.sticker("stk_x_abc")
        with pytest.raises(RuntimeError, match="asset_library"):
            StickerSender().send(ctx, ["A"], msg)

    def test_reject_unknown_tag(self, sender, ctx):
        msg = Message.sticker("stk_不存在_ffffff")
        with pytest.raises(KeyError):
            sender.send(ctx, ["A"], msg)

    def test_reject_type_mismatch(self, sender, ctx, lib):
        entry = lib.register_forward(
            semantic_type=MessageType.LOCATION, fta_locator="北京"
        )
        msg = Message.sticker(entry.tag)
        with pytest.raises(ValueError, match="semantic_type"):
            sender.send(ctx, ["A"], msg)

    def test_reject_missing_locator(self, sender, ctx, lib):
        bad = AssetEntry(
            tag="stk_bad_000000",
            semantic_type=MessageType.STICKER,
            fta_locator=None,
        )
        lib._upsert_raw(bad)
        msg = Message.sticker("stk_bad_000000")
        with pytest.raises(ValueError, match="fta_locator"):
            sender.send(ctx, ["A"], msg)


# ================== 正常发送 ================== #


class TestSend:
    def test_delegates_to_nav_send_sticker(
        self, sender, ctx, mock_nav, stk_tag
    ):
        msg = Message.sticker(stk_tag)
        sender.send(ctx, ["张三"], msg)

        mock_nav.send_sticker.assert_called_once()
        args, kwargs = mock_nav.send_sticker.call_args
        assert args[0] == "idx:0"
        assert kwargs.get("after_send_s") == 1.2

    def test_default_wait_no_cfg(self, mock_nav, lib, stk_tag):
        ctx = SendContext(nav=mock_nav, cfg=None, asset_library=lib)
        msg = Message.sticker(stk_tag)
        StickerSender().send(ctx, ["A"], msg)
        _, kwargs = mock_nav.send_sticker.call_args
        assert kwargs.get("after_send_s") == 1.0

    def test_propagates_nav_exception(self, sender, ctx, mock_nav, stk_tag):
        mock_nav.send_sticker.side_effect = RuntimeError("表情面板打不开")
        msg = Message.sticker(stk_tag)
        with pytest.raises(RuntimeError, match="表情面板"):
            sender.send(ctx, ["A"], msg)
