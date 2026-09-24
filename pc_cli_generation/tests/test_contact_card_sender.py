"""
Stage 4.5.6 ContactCardSender 单元测试.

用 mock nav, 不需要真机.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.messaging.sender import SendContext, SenderRegistry, is_forward_sender
from app.messaging.senders.contact_card import ContactCardSender
from app.messaging.types import DIRECT_SEND_TYPES, Message, MessageType


# ======================== Fixtures ======================== #

@pytest.fixture
def mock_nav():
    return MagicMock()


@pytest.fixture
def mock_cfg():
    """带 timing.after_send_wait_s 的 mock cfg"""
    cfg = MagicMock()
    cfg.timing.after_send_wait_s = 1.5
    return cfg


@pytest.fixture
def ctx(mock_nav, mock_cfg):
    return SendContext(nav=mock_nav, cfg=mock_cfg)


@pytest.fixture
def sender():
    return ContactCardSender()


# ======================== 契约 ======================== #


class TestContract:
    def test_supported_type_only_contact_card(self, sender):
        assert sender.supported_types == frozenset({MessageType.CONTACT_CARD})

    def test_is_direct_sender(self, sender):
        # CONTACT_CARD 应属 DIRECT_SEND_TYPES
        assert not is_forward_sender(sender)
        assert MessageType.CONTACT_CARD in DIRECT_SEND_TYPES

    def test_can_register_in_registry(self, sender):
        reg = SenderRegistry()
        reg.register(sender)
        assert MessageType.CONTACT_CARD in reg


# ======================== 输入校验 ======================== #


class TestValidation:
    def test_reject_wrong_type(self, sender, ctx):
        msg = Message.text_msg("hi")
        with pytest.raises(ValueError, match="只接收 CONTACT_CARD"):
            sender.send(ctx, ["张三"], msg)

    def test_reject_multi_targets(self, sender, ctx):
        msg = Message.contact_card("好友A")
        with pytest.raises(ValueError, match="只发单个联系人"):
            sender.send(ctx, ["张三", "李四"], msg)

    def test_reject_empty_targets(self, sender, ctx):
        msg = Message.contact_card("好友A")
        with pytest.raises(ValueError, match="只发单个联系人"):
            sender.send(ctx, [], msg)

    def test_reject_missing_nav(self, mock_cfg):
        sender = ContactCardSender()
        ctx = SendContext(nav=None, cfg=mock_cfg)
        msg = Message.contact_card("好友A")
        with pytest.raises(RuntimeError, match="nav"):
            sender.send(ctx, ["张三"], msg)

    def test_reject_empty_friend_name(self, sender, ctx):
        # Message 模型层已阻止 friend_name 为空的 CONTACT_CARD 构造,
        # 所以走 Message 构造是校验不到的; 用 model_construct 绕过
        msg = Message.model_construct(
            type=MessageType.CONTACT_CARD, friend_name=None
        )
        with pytest.raises(ValueError, match="friend_name"):
            sender.send(ctx, ["张三"], msg)


# ======================== 正常发送 ======================== #


class TestSend:
    def test_calls_nav_send_contact_card(self, sender, ctx, mock_nav):
        msg = Message.contact_card("好友A")
        sender.send(ctx, ["张三"], msg)

        mock_nav.send_contact_card.assert_called_once()
        args, kwargs = mock_nav.send_contact_card.call_args
        assert args[0] == "好友A"
        # after_send_s 应传自 cfg
        assert kwargs.get("after_send_s") == 1.5

    def test_strips_friend_name(self, sender, ctx, mock_nav):
        msg = Message.contact_card("  好友B  ")
        sender.send(ctx, ["张三"], msg)
        # Message 构造时已经 strip 过, 但 sender 也再 strip 一次防御
        args, _ = mock_nav.send_contact_card.call_args
        assert args[0] == "好友B"

    def test_default_wait_when_no_cfg(self, mock_nav):
        sender = ContactCardSender()
        ctx = SendContext(nav=mock_nav, cfg=None)
        msg = Message.contact_card("好友A")
        sender.send(ctx, ["张三"], msg)
        # cfg=None 时应回落到 1.0
        _, kwargs = mock_nav.send_contact_card.call_args
        assert kwargs.get("after_send_s") == 1.0

    def test_bad_cfg_falls_back_to_default(self, mock_nav):
        """cfg 存在但读 timing 抛异常时应回落"""
        cfg = MagicMock()
        cfg.timing.after_send_wait_s = "not-a-float"  # 触发 float() 异常
        sender = ContactCardSender()
        ctx = SendContext(nav=mock_nav, cfg=cfg)
        msg = Message.contact_card("好友A")
        sender.send(ctx, ["张三"], msg)
        _, kwargs = mock_nav.send_contact_card.call_args
        assert kwargs.get("after_send_s") == 1.0

    def test_propagates_nav_exception(self, sender, ctx, mock_nav):
        """Navigator 抛异常时 sender 也应抛出 (让 BatchRunner 决定策略)"""
        mock_nav.send_contact_card.side_effect = RuntimeError("UI 定位失败")
        msg = Message.contact_card("好友A")
        with pytest.raises(RuntimeError, match="UI 定位失败"):
            sender.send(ctx, ["张三"], msg)
