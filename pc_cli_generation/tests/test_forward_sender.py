"""
Stage 4.5.5.3 ForwardSender 单元测试.

用 mock nav + 内存 AssetLibrary, 不需要真机.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.messaging.asset_library import AssetLibrary
from app.messaging.sender import SendContext, SenderRegistry, is_forward_sender
from app.messaging.senders.forward import ForwardSender
from app.messaging.types import FORWARD_TYPES, Message, MessageType


# ======================== Fixtures ======================== #

@pytest.fixture
def lib(tmp_path):
    """空的 AssetLibrary (临时目录, 不影响 runtime/asset_library.json)"""
    return AssetLibrary(tmp_path / "asset_library.json")


@pytest.fixture
def mp_tag(lib):
    """注册一个小程序转发素材, 返回其 tag"""
    entry = lib.register_forward(
        semantic_type=MessageType.MINIPROGRAM,
        fta_locator="商品A 小程序",
        display_name="商品A",
    )
    return entry.tag


@pytest.fixture
def mock_nav():
    nav = MagicMock()
    return nav


@pytest.fixture
def ctx(mock_nav, lib):
    return SendContext(dev=None, nav=mock_nav, cfg=None, asset_library=lib)


@pytest.fixture
def sender():
    """默认 sender 用 single 模式, 兼容 4.5.5.3 老测试 (单选循环)"""
    return ForwardSender(mode="single")


@pytest.fixture
def sender_auto():
    """4.5.7: auto 模式 (N>=2 走多选, missed 回退单选)"""
    return ForwardSender(mode="auto")


@pytest.fixture
def sender_multi():
    """4.5.7: strict multi 模式 (missed 抛异常, 不回退)"""
    return ForwardSender(mode="multi")


# ======================== 基础契约 ======================== #


class TestContract:
    def test_supported_types_is_forward_types(self, sender):
        assert sender.supported_types == FORWARD_TYPES

    def test_is_forward_sender_true(self, sender):
        assert is_forward_sender(sender)

    def test_can_register_in_registry(self, sender):
        """ForwardSender 应能被 SenderRegistry 接收 (纯 forward 类别)"""
        reg = SenderRegistry()
        reg.register(sender)
        for t in FORWARD_TYPES:
            assert t in reg


# ======================== 输入校验 ======================== #


class TestValidation:
    def test_reject_wrong_type(self, sender, ctx):
        msg = Message.text_msg("hi")
        with pytest.raises(ValueError, match="只接收"):
            sender.send(ctx, ["张三"], msg)

    def test_reject_empty_targets(self, sender, ctx, mp_tag):
        msg = Message.miniprogram(mp_tag)
        with pytest.raises(ValueError, match="targets 不能为空"):
            sender.send(ctx, [], msg)

    def test_reject_missing_nav(self, sender, lib, mp_tag):
        ctx = SendContext(nav=None, asset_library=lib)
        msg = Message.miniprogram(mp_tag)
        with pytest.raises(RuntimeError, match="nav"):
            sender.send(ctx, ["张三"], msg)

    def test_reject_missing_asset_library(self, sender, mock_nav, mp_tag):
        # mp_tag 只是用来生成一个已知 tag; ctx 里不给 lib
        ctx = SendContext(nav=mock_nav, asset_library=None)
        msg = Message.miniprogram("mp_商品A_abc123")
        with pytest.raises(RuntimeError, match="asset_library"):
            sender.send(ctx, ["张三"], msg)

    def test_reject_unknown_tag(self, sender, ctx):
        msg = Message.miniprogram("mp_不存在_ffffff")
        with pytest.raises(KeyError):
            sender.send(ctx, ["张三"], msg)

    def test_reject_type_mismatch(self, sender, ctx, lib):
        """tag 对应的 semantic_type 与消息 type 不一致时应拒绝"""
        entry = lib.register_forward(
            semantic_type=MessageType.LOCATION,
            fta_locator="北京市朝阳区",
        )
        # 用 miniprogram 类型引用一个 location tag
        msg = Message.miniprogram(entry.tag)
        with pytest.raises(ValueError, match="semantic_type"):
            sender.send(ctx, ["张三"], msg)

    def test_reject_entry_without_locator(self, sender, ctx, lib):
        """
        AssetEntry.fta_locator 为空的情况下应拒绝.
        用 _upsert_raw 绕过 register_forward 的校验来构造非法条目.
        """
        from app.messaging.asset_library import AssetEntry
        bad = AssetEntry(
            tag="mp_bad_000000",
            semantic_type=MessageType.MINIPROGRAM,
            fta_locator=None,
        )
        lib._upsert_raw(bad)
        msg = Message.miniprogram("mp_bad_000000")
        with pytest.raises(ValueError, match="fta_locator"):
            sender.send(ctx, ["张三"], msg)


# ======================== 单人转发 ======================== #


class TestSingleTarget:
    def test_calls_open_fta_and_forward(self, sender, ctx, mock_nav, mp_tag):
        msg = Message.miniprogram(mp_tag)
        sender.send(ctx, ["张三"], msg)

        mock_nav.open_fta.assert_called_once()
        mock_nav.forward_bubble_to.assert_called_once_with(
            "商品A 小程序", "张三"
        )

    def test_location_type(self, sender, ctx, mock_nav, lib):
        entry = lib.register_forward(
            semantic_type=MessageType.LOCATION,
            fta_locator="北京市朝阳区",
        )
        msg = Message.location(entry.tag)
        sender.send(ctx, ["李四"], msg)

        mock_nav.forward_bubble_to.assert_called_once_with(
            "北京市朝阳区", "李四"
        )

    def test_channel_video_type(self, sender, ctx, mock_nav, lib):
        entry = lib.register_forward(
            semantic_type=MessageType.CHANNEL_VIDEO,
            fta_locator="视频号:某某官方",
        )
        msg = Message.channel_video(entry.tag)
        sender.send(ctx, ["王五"], msg)

        mock_nav.forward_bubble_to.assert_called_once_with(
            "视频号:某某官方", "王五"
        )


# ======================== 多人循环 ======================== #


class TestMultiTargets:
    def test_forwards_to_each(self, sender, ctx, mock_nav, mp_tag):
        msg = Message.miniprogram(mp_tag)
        sender.send(ctx, ["张三", "李四", "王五"], msg)

        assert mock_nav.forward_bubble_to.call_count == 3
        calls = mock_nav.forward_bubble_to.call_args_list
        assert calls[0].args == ("商品A 小程序", "张三")
        assert calls[1].args == ("商品A 小程序", "李四")
        assert calls[2].args == ("商品A 小程序", "王五")

    def test_open_fta_called_between_targets(
        self, sender, ctx, mock_nav, mp_tag
    ):
        """
        3 人 → open_fta 应调用 3 次 (首次 + 2 次轮次间; 最后一轮不需要)
        """
        msg = Message.miniprogram(mp_tag)
        sender.send(ctx, ["A", "B", "C"], msg)
        assert mock_nav.open_fta.call_count == 3

    def test_open_fta_once_for_single_target(
        self, sender, ctx, mock_nav, mp_tag
    ):
        msg = Message.miniprogram(mp_tag)
        sender.send(ctx, ["only_one"], msg)
        assert mock_nav.open_fta.call_count == 1


# ======================== 错误恢复 ======================== #


class TestErrorRecovery:
    def test_partial_failure_raises_after_loop(
        self, sender, ctx, mock_nav, mp_tag
    ):
        """
        中间某个联系人失败, 应继续尝试后面的, 最后汇总抛异常.
        """
        # 第 2 个联系人 (李四) 失败
        def forward_side_effect(locator, contact):
            if contact == "李四":
                raise RuntimeError("模拟 UI 定位失败")

        mock_nav.forward_bubble_to.side_effect = forward_side_effect
        msg = Message.miniprogram(mp_tag)
        with pytest.raises(RuntimeError, match="部分失败.*李四"):
            sender.send(ctx, ["张三", "李四", "王五"], msg)

        # 三个联系人都尝试过
        assert mock_nav.forward_bubble_to.call_count == 3

    def test_recover_open_fta_after_failure(
        self, sender, ctx, mock_nav, mp_tag
    ):
        """失败后应调用 open_fta 尝试恢复"""
        def forward_side_effect(locator, contact):
            if contact == "李四":
                raise RuntimeError("fail")

        mock_nav.forward_bubble_to.side_effect = forward_side_effect
        msg = Message.miniprogram(mp_tag)
        with pytest.raises(RuntimeError):
            sender.send(ctx, ["张三", "李四", "王五"], msg)

        # open_fta: 初始 1 次 + 张三后 1 次 + 李四失败恢复 1 次 = 3 次
        # (王五是最后一个, 不再 open_fta)
        assert mock_nav.open_fta.call_count == 3

    def test_all_success_no_error(self, sender, ctx, mock_nav, mp_tag):
        """全部成功不应抛异常"""
        msg = Message.miniprogram(mp_tag)
        sender.send(ctx, ["A", "B"], msg)  # 不 raise 即通过


# ============================================================ #
#            Stage 4.5.7: auto / multi 模式                    #
# ============================================================ #


class TestConstructor:
    def test_default_mode_auto(self):
        assert ForwardSender().mode == "auto"

    def test_explicit_modes(self):
        assert ForwardSender(mode="auto").mode == "auto"
        assert ForwardSender(mode="single").mode == "single"
        assert ForwardSender(mode="multi").mode == "multi"

    def test_reject_bad_mode(self):
        with pytest.raises(ValueError, match="未知 mode"):
            ForwardSender(mode="bogus")  # type: ignore[arg-type]


class TestAutoMode:
    """默认 mode=auto: 单人走单选, 多人走多选"""

    def test_single_target_uses_single_path(
        self, sender_auto, ctx, mock_nav, mp_tag
    ):
        mock_nav.forward_bubble_multi.return_value = []
        msg = Message.miniprogram(mp_tag)
        sender_auto.send(ctx, ["张三"], msg)

        mock_nav.forward_bubble_to.assert_called_once_with(
            "商品A 小程序", "张三"
        )
        mock_nav.forward_bubble_multi.assert_not_called()

    def test_multi_target_uses_multi_path(
        self, sender_auto, ctx, mock_nav, mp_tag
    ):
        mock_nav.forward_bubble_multi.return_value = []
        msg = Message.miniprogram(mp_tag)
        sender_auto.send(ctx, ["A", "B", "C"], msg)

        mock_nav.forward_bubble_multi.assert_called_once_with(
            "商品A 小程序", ["A", "B", "C"]
        )
        # 未回退, 单选不应被调用
        mock_nav.forward_bubble_to.assert_not_called()

    def test_multi_path_open_fta_once(
        self, sender_auto, ctx, mock_nav, mp_tag
    ):
        """多选路径 open_fta 应只调 1 次 (对比单选路径每人前都调)"""
        mock_nav.forward_bubble_multi.return_value = []
        msg = Message.miniprogram(mp_tag)
        sender_auto.send(ctx, ["A", "B", "C"], msg)
        assert mock_nav.open_fta.call_count == 1


class TestAutoModeFallback:
    """auto 模式下, 多选未勾中的联系人应回退单选"""

    def test_missed_are_retried_via_single(
        self, sender_auto, ctx, mock_nav, mp_tag
    ):
        # 3 人中李四勾不上
        mock_nav.forward_bubble_multi.return_value = ["李四"]
        msg = Message.miniprogram(mp_tag)
        sender_auto.send(ctx, ["张三", "李四", "王五"], msg)

        # 单选路径应只处理 missed 的李四, 一次
        mock_nav.forward_bubble_to.assert_called_once_with(
            "商品A 小程序", "李四"
        )

    def test_missed_open_fta_transition(
        self, sender_auto, ctx, mock_nav, mp_tag
    ):
        """多选完 → 回退前 open_fta 一次 → 单选 1 人 (不再 open_fta 因为是唯一)"""
        mock_nav.forward_bubble_multi.return_value = ["李四"]
        msg = Message.miniprogram(mp_tag)
        sender_auto.send(ctx, ["张三", "李四", "王五"], msg)
        # open_fta: 初始 1 + 回退前 1 = 2 (missed 只有 1 人, 单选内不再 open_fta)
        assert mock_nav.open_fta.call_count == 2

    def test_fallback_multiple_missed(
        self, sender_auto, ctx, mock_nav, mp_tag
    ):
        mock_nav.forward_bubble_multi.return_value = ["B", "C"]
        msg = Message.miniprogram(mp_tag)
        sender_auto.send(ctx, ["A", "B", "C"], msg)
        # 单选应处理 B、C 两人
        calls = mock_nav.forward_bubble_to.call_args_list
        assert [c.args for c in calls] == [
            ("商品A 小程序", "B"),
            ("商品A 小程序", "C"),
        ]

    def test_all_missed_falls_back_completely(
        self, sender_auto, ctx, mock_nav, mp_tag
    ):
        """多选一个也没勾中 → 全部走单选"""
        mock_nav.forward_bubble_multi.return_value = ["A", "B"]
        msg = Message.miniprogram(mp_tag)
        sender_auto.send(ctx, ["A", "B"], msg)
        assert mock_nav.forward_bubble_to.call_count == 2


class TestMultiModeStrict:
    """mode=multi: 严格模式, missed 抛异常, 不回退"""

    def test_all_success_no_error(
        self, sender_multi, ctx, mock_nav, mp_tag
    ):
        mock_nav.forward_bubble_multi.return_value = []
        msg = Message.miniprogram(mp_tag)
        sender_multi.send(ctx, ["A", "B"], msg)
        mock_nav.forward_bubble_to.assert_not_called()

    def test_missed_raises_and_no_fallback(
        self, sender_multi, ctx, mock_nav, mp_tag
    ):
        mock_nav.forward_bubble_multi.return_value = ["B"]
        msg = Message.miniprogram(mp_tag)
        with pytest.raises(RuntimeError, match="未勾中.*B"):
            sender_multi.send(ctx, ["A", "B"], msg)
        # 严格模式不 fallback
        mock_nav.forward_bubble_to.assert_not_called()

    def test_single_target_still_uses_single_path(
        self, sender_multi, ctx, mock_nav, mp_tag
    ):
        """即使 mode=multi, 单人也仍走单选 (多选无意义)"""
        msg = Message.miniprogram(mp_tag)
        sender_multi.send(ctx, ["only"], msg)
        mock_nav.forward_bubble_to.assert_called_once()
        mock_nav.forward_bubble_multi.assert_not_called()
