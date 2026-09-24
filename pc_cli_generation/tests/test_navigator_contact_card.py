"""
Stage 4.5.6 WeComNavigator 个人名片方法 单元测试.

方法: open_contact_card_picker / pick_friend_for_card / confirm_card_send /
      send_contact_card (组合).

用 mock u2.Device.
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


# ======================== open_contact_card_picker ======================== #


class TestOpenContactCardPicker:
    def test_finds_entry_and_waits_for_picker(self, nav, mock_dev):
        """+ 面板已展开 + 个人名片入口可见 + 搜索栏出现 → 成功"""
        # 关键: "相册"入口需先可见, open_plus_panel 会认为面板已开
        gallery_el = MagicMock()
        gallery_el.exists = True

        card_entry = MagicMock()
        card_entry.exists = True
        # click 一次即可

        edit = MagicMock()
        edit.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "相册":
                return gallery_el
            if kwargs.get("text") == "个人名片":
                return card_entry
            if kwargs.get("className") == "android.widget.EditText":
                return edit
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.open_contact_card_picker(timeout_s=1.0)
        card_entry.click.assert_called_once()

    def test_no_entry_raises(self, nav, mock_dev):
        """附件面板打开了, 但翻页都找不到个人名片入口 → NavigationError"""
        gallery_el = MagicMock()
        gallery_el.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "相册":
                return gallery_el
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="个人名片"):
            nav.open_contact_card_picker(timeout_s=0.3)

    def test_picker_ui_timeout_raises(self, nav, mock_dev):
        """点击入口后, 好友选择器没出现 (无 EditText / ListView) → 超时"""
        gallery_el = MagicMock()
        gallery_el.exists = True

        card_entry = MagicMock()
        card_entry.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "相册":
                return gallery_el
            if kwargs.get("text") == "个人名片":
                return card_entry
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="选择器加载超时"):
            nav.open_contact_card_picker(timeout_s=0.3)


# ======================== pick_friend_for_card ======================== #


class TestPickFriendForCard:
    def test_direct_hit_in_list(self, nav, mock_dev):
        friend_el = MagicMock()
        friend_el.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "好友A":
                return friend_el
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.pick_friend_for_card("好友A")
        friend_el.click.assert_called_once()

    def test_search_fallback(self, nav, mock_dev):
        """列表未见 → 点搜索图标 → 输入 → 结果命中"""
        friend_el = MagicMock()
        friend_el.exists = True

        search_icon = MagicMock()
        search_icon.exists = True

        edit_el = MagicMock()
        edit_el.exists = True

        sent = {"done": False}

        def sel(**kwargs):
            if kwargs.get("text") == "好友B":
                return friend_el if sent["done"] else _miss()
            if kwargs.get("textContains") == "好友B":
                return friend_el if sent["done"] else _miss()
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt8":
                return search_icon
            if kwargs.get("className") == "android.widget.EditText":
                return edit_el
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel

        orig_send = mock_dev.send_keys
        def fake_send(t):
            sent["done"] = True
            return orig_send(t)
        mock_dev.send_keys = fake_send

        nav.pick_friend_for_card("好友B")
        friend_el.click.assert_called()

    def test_search_result_miss_raises(self, nav, mock_dev):
        search_icon = MagicMock()
        search_icon.exists = True

        edit_el = MagicMock()
        edit_el.exists = True

        def sel(**kwargs):
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt8":
                return search_icon
            if kwargs.get("className") == "android.widget.EditText":
                return edit_el
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()

        with pytest.raises(NavigationError, match="搜索"):
            nav.pick_friend_for_card("不存在好友")

    def test_no_search_entry_raises(self, nav, mock_dev):
        """列表未见 + 无搜索图标 + 无 EditText → 报错"""
        def sel(**kwargs):
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()

        with pytest.raises(NavigationError, match="找不到搜索"):
            nav.pick_friend_for_card("好友X")


# ======================== confirm_card_send ======================== #


class TestConfirmCardSend:
    def test_clicks_send_button(self, nav, mock_dev):
        send_btn = MagicMock()
        send_btn.exists = True

        def sel(**kwargs):
            if (kwargs.get("text") == "发送"
                    and kwargs.get("className") == "android.widget.Button"):
                return send_btn
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.confirm_card_send(timeout_s=0.5)
        send_btn.click.assert_called_once()

    def test_no_dialog_does_not_raise(self, nav, mock_dev):
        def sel(**kwargs):
            return _miss()
        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.confirm_card_send(timeout_s=0.2)


# ======================== send_contact_card (组合) ======================== #


class TestSendContactCard:
    def test_full_flow(self, nav, mock_dev):
        """完整链路: 打开面板→个人名片→选人→确认"""
        gallery_el = MagicMock()
        gallery_el.exists = True

        card_entry = MagicMock()
        card_entry.exists = True

        edit = MagicMock()
        edit.exists = True

        friend_el = MagicMock()
        friend_el.exists = True

        send_btn = MagicMock()
        send_btn.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "相册":
                return gallery_el
            if kwargs.get("text") == "个人名片":
                return card_entry
            if kwargs.get("className") == "android.widget.EditText":
                return edit
            if kwargs.get("text") == "好友A":
                return friend_el
            if (kwargs.get("text") == "发送"
                    and kwargs.get("className") == "android.widget.Button"):
                return send_btn
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.send_contact_card("好友A", after_send_s=0.1)

        card_entry.click.assert_called_once()  # 点了个人名片
        friend_el.click.assert_called_once()   # 选了好友
        send_btn.click.assert_called_once()    # 确认发送
