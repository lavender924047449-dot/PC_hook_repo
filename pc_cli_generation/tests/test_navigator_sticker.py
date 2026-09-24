"""
Stage 4.5.8 WeComNavigator 收藏表情方法 单元测试.

方法:
    open_emoji_panel
    switch_to_favorite_stickers
    _parse_sticker_locator (静态)
    pick_sticker_by_locator (idx / desc)
    send_sticker (组合)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.automation.navigator import NavigationError, WeComNavigator
from app.config import LocatorsConfig


SAMPLE_LOCATORS = LocatorsConfig(
    mic_toggle="com.tencent.wework:id/gif",
    hold_button="com.tencent.wework:id/ijs",
    input_edit="com.tencent.wework:id/iju",
    home_msg_tab_text="消息",
)

# 收藏表情面板 dump: 一个 RecyclerView 里有 4 张缩略图 (方形, ~200x200)
STICKER_PANEL_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node class="android.widget.LinearLayout" bounds="[0,0][720,1280]">
    <node class="androidx.recyclerview.widget.RecyclerView"
          bounds="[0,700][720,1280]">
      <node class="android.widget.ImageView"
            clickable="true" bounds="[10,720][210,920]"
            content-desc="猫咪" />
      <node class="android.widget.ImageView"
            clickable="true" bounds="[220,720][420,920]"
            content-desc="狗狗" />
      <node class="android.widget.ImageView"
            clickable="true" bounds="[430,720][630,920]"
            content-desc="" />
      <node class="android.widget.ImageView"
            clickable="true" bounds="[10,940][210,1140]"
            content-desc="wow" />
    </node>
  </node>
</hierarchy>
"""


@pytest.fixture
def mock_dev():
    dev = MagicMock()
    dev.info = {"displayWidth": 720, "displayHeight": 1280}
    return dev


@pytest.fixture
def nav(mock_dev):
    return WeComNavigator(mock_dev, SAMPLE_LOCATORS)


def _miss():
    m = MagicMock()
    m.exists = False
    return m


# ================== _parse_sticker_locator ================== #


class TestParseStickerLocator:
    def test_idx_prefix(self):
        assert WeComNavigator._parse_sticker_locator("idx:3") == ("idx", "3")

    def test_bare_digit(self):
        assert WeComNavigator._parse_sticker_locator("0") == ("idx", "0")
        assert WeComNavigator._parse_sticker_locator("42") == ("idx", "42")

    def test_desc_prefix(self):
        assert WeComNavigator._parse_sticker_locator("desc:猫咪") == (
            "desc", "猫咪"
        )

    def test_whitespace_trimmed(self):
        assert WeComNavigator._parse_sticker_locator("  idx:5  ") == (
            "idx", "5"
        )

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="不能为空"):
            WeComNavigator._parse_sticker_locator("")

    def test_idx_non_digit_raises(self):
        with pytest.raises(ValueError, match="非负整数"):
            WeComNavigator._parse_sticker_locator("idx:abc")

    def test_desc_empty_raises(self):
        with pytest.raises(ValueError, match="desc"):
            WeComNavigator._parse_sticker_locator("desc:")

    def test_unknown_syntax_raises(self):
        with pytest.raises(ValueError, match="未知"):
            WeComNavigator._parse_sticker_locator("foo:bar")


# ================== open_emoji_panel ================== #


class TestOpenEmojiPanel:
    def test_idempotent_if_favorites_tab_visible(self, nav, mock_dev):
        """收藏 tab 已可见 → 直接返回, 不点按钮"""
        fav = MagicMock()
        fav.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "收藏":
                return fav
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.open_emoji_panel()
        # 不应触发点击 emoji 按钮

    def test_clicks_emoji_button_then_waits_for_tab(self, nav, mock_dev):
        btn = MagicMock()
        btn.exists = True
        fav = MagicMock()
        fav.exists = False  # 初始不见, 点击后出现

        clicked = {"n": 0}

        def sel(**kwargs):
            if kwargs.get("text") == "收藏":
                if clicked["n"] > 0:
                    m = MagicMock()
                    m.exists = True
                    return m
                return _miss()
            if kwargs.get("description") == "表情":
                return btn
            # input_edit / 其他一律 miss (让 enter_text_mode 失败被吞掉)
            return _miss()

        def clk():
            clicked["n"] += 1
        btn.click.side_effect = clk

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.open_emoji_panel(timeout_s=1.0)
        btn.click.assert_called_once()

    def test_missing_button_raises(self, nav, mock_dev):
        def sel(**kwargs):
            return _miss()
        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="emoji"):
            nav.open_emoji_panel(timeout_s=0.3)


# ================== switch_to_favorite_stickers ================== #


class TestSwitchToFavorite:
    def test_clicks_tab(self, nav, mock_dev):
        fav = MagicMock()
        fav.exists = True
        grid = MagicMock()
        grid.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "收藏":
                return fav
            if kwargs.get("className") == (
                "androidx.recyclerview.widget.RecyclerView"
            ):
                return grid
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.switch_to_favorite_stickers(timeout_s=0.5)
        fav.click.assert_called_once()

    def test_missing_tab_raises(self, nav, mock_dev):
        def sel(**kwargs):
            return _miss()
        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="收藏"):
            nav.switch_to_favorite_stickers()


# ================== pick_sticker_by_locator ================== #


class TestPickStickerByLocator:
    def test_desc_hit(self, nav, mock_dev):
        el = MagicMock()
        el.exists = True

        def sel(**kwargs):
            if kwargs.get("description") == "猫咪":
                return el
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.pick_sticker_by_locator("desc:猫咪")
        el.click.assert_called_once()

    def test_desc_miss_raises(self, nav, mock_dev):
        def sel(**kwargs):
            return _miss()
        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="未找到 desc"):
            nav.pick_sticker_by_locator("desc:不存在")

    def test_idx_zero_taps_first(self, nav, mock_dev):
        """idx=0 应点第一个缩略图"""
        mock_dev.dump_hierarchy.return_value = STICKER_PANEL_XML
        nav.pick_sticker_by_locator("idx:0")
        # 第一张 bounds=[10,720][210,920] → 中心 (110, 820)
        mock_dev.click.assert_called_once_with(110, 820)

    def test_idx_two_taps_third(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = STICKER_PANEL_XML
        nav.pick_sticker_by_locator("idx:2")
        # 第三张 bounds=[430,720][630,920] → 中心 (530, 820)
        mock_dev.click.assert_called_once_with(530, 820)

    def test_idx_out_of_range_raises(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = STICKER_PANEL_XML
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="第 99"):
            nav.pick_sticker_by_locator("idx:99")

    def test_bare_digit_treated_as_idx(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = STICKER_PANEL_XML
        nav.pick_sticker_by_locator("1")
        # 第二张 bounds=[220,720][420,920] → 中心 (320, 820)
        mock_dev.click.assert_called_once_with(320, 820)


# ================== send_sticker (组合) ================== #


class TestSendSticker:
    def test_full_flow_idx(self, nav, mock_dev):
        """完整链路: emoji 按钮 → 收藏 tab → 点缩略图"""
        emoji_btn = MagicMock()
        emoji_btn.exists = True
        fav_tab = MagicMock()
        # 一开始 tab 不见 (触发点击 emoji 按钮), 之后可见
        state = {"opened": False}

        def sel(**kwargs):
            if kwargs.get("text") == "收藏":
                m = MagicMock()
                m.exists = state["opened"]
                return m
            if kwargs.get("description") == "表情":
                return emoji_btn
            if kwargs.get("className") == (
                "androidx.recyclerview.widget.RecyclerView"
            ):
                m = MagicMock()
                m.exists = state["opened"]
                return m
            return _miss()

        def open_emoji():
            state["opened"] = True
        emoji_btn.click.side_effect = open_emoji

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = STICKER_PANEL_XML

        nav.send_sticker("idx:0", after_send_s=0.05)
        emoji_btn.click.assert_called_once()
        # 收藏 tab 被点击
        # (fav MagicMock 每次 sel 调用都是新的实例, 只验证 emoji + 最终 click 到坐标)
        mock_dev.click.assert_called_once_with(110, 820)
