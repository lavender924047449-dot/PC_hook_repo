"""
Stage 4.5.7 WeComNavigator 多选群发相关方法 单元测试.

方法:
    enter_multi_select_mode
    tick_contact_in_multi_select
    tap_multi_select_done
    forward_bubble_multi (组合)
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

# 与 test_navigator_fta.py 相同的 FTA 气泡 XML
FTA_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node class="android.widget.FrameLayout" bounds="[0,0][720,1280]">
    <node class="androidx.recyclerview.widget.RecyclerView"
          bounds="[0,100][720,1100]" scrollable="true">
      <node class="android.widget.RelativeLayout"
            long-clickable="true" clickable="true"
            bounds="[50,200][670,350]">
        <node class="android.widget.TextView" text="商品A 小程序"
              bounds="[60,210][400,260]" />
      </node>
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


# ================== enter_multi_select_mode ================== #


class TestEnterMultiSelectMode:
    def test_clicks_icon(self, nav, mock_dev):
        icon = MagicMock()
        icon.exists = True
        done_btn = MagicMock()
        done_btn.exists = True

        clicked = {"n": 0}

        def sel(**kwargs):
            # 底部完成按钮: 第一次不存在 (还没进多选), 之后存在
            if kwargs.get("resourceId") == "com.tencent.wework:id/lt5":
                return done_btn if clicked["n"] > 0 else _miss()
            if kwargs.get("textStartsWith") in ("发送", "完成", "确定"):
                return done_btn if clicked["n"] > 0 else _miss()
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt3":
                return icon
            return _miss()

        def icon_click():
            clicked["n"] += 1
        icon.click.side_effect = icon_click

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.enter_multi_select_mode(timeout_s=1.0)
        icon.click.assert_called_once()

    def test_idempotent_when_already_multi(self, nav, mock_dev):
        """底部完成按钮已在 → 视为已多选, 不再点图标"""
        done_btn = MagicMock()
        done_btn.exists = True
        icon = MagicMock()
        icon.exists = True

        def sel(**kwargs):
            if kwargs.get("resourceId") == "com.tencent.wework:id/lt5":
                return done_btn
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt3":
                return icon
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.enter_multi_select_mode()
        icon.click.assert_not_called()

    def test_no_icon_raises(self, nav, mock_dev):
        def sel(**kwargs):
            return _miss()
        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="多选图标"):
            nav.enter_multi_select_mode()


# ================== tick_contact_in_multi_select ================== #


class TestTickContactInMultiSelect:
    def test_direct_hit_returns_true(self, nav, mock_dev):
        el = MagicMock()
        el.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "张三":
                return el
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        assert nav.tick_contact_in_multi_select("张三") is True
        el.click.assert_called_once()

    def test_no_search_when_disabled(self, nav, mock_dev):
        """search_if_missing=False 时列表未见即返回 False, 不走搜索"""
        search_icon = MagicMock()
        search_icon.exists = True

        def sel(**kwargs):
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt8":
                return search_icon
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        assert nav.tick_contact_in_multi_select(
            "李四", search_if_missing=False
        ) is False
        search_icon.click.assert_not_called()

    def test_search_fallback_success(self, nav, mock_dev):
        contact_el = MagicMock()
        contact_el.exists = True
        search_icon = MagicMock()
        search_icon.exists = True
        edit_el = MagicMock()
        edit_el.exists = True

        sent = {"done": False}

        def sel(**kwargs):
            if kwargs.get("text") == "李四":
                return contact_el if sent["done"] else _miss()
            if kwargs.get("textContains") == "李四":
                return contact_el if sent["done"] else _miss()
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

        assert nav.tick_contact_in_multi_select("李四") is True

    def test_search_miss_returns_false(self, nav, mock_dev):
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
        assert nav.tick_contact_in_multi_select("不存在") is False

    def test_no_search_entry_returns_false(self, nav, mock_dev):
        def sel(**kwargs):
            return _miss()
        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        assert nav.tick_contact_in_multi_select("X") is False


# ================== tap_multi_select_done ================== #


class TestTapMultiSelectDone:
    def test_clicks_done_button(self, nav, mock_dev):
        done_btn = MagicMock()
        done_btn.exists = True

        def sel(**kwargs):
            if kwargs.get("resourceId") == "com.tencent.wework:id/lt5":
                return done_btn
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.tap_multi_select_done(timeout_s=0.5)
        done_btn.click.assert_called_once()

    def test_missing_raises(self, nav, mock_dev):
        def sel(**kwargs):
            return _miss()
        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="完成/发送"):
            nav.tap_multi_select_done(timeout_s=0.3)


# ================== forward_bubble_multi (组合) ================== #


class TestForwardBubbleMulti:
    def test_reject_empty_contacts(self, nav):
        with pytest.raises(ValueError, match="contacts 不能为空"):
            nav.forward_bubble_multi("locator", [])

    def test_full_success_returns_empty_missed(self, nav, mock_dev):
        """全部勾中: 长按→转发→多选→勾3人→完成→确认; 返回 []"""
        mock_dev.dump_hierarchy.return_value = FTA_XML

        fwd_menu = MagicMock()
        fwd_menu.exists = True
        icon = MagicMock()
        icon.exists = True
        done_btn = MagicMock()
        done_btn.exists = True
        contact_a = MagicMock()
        contact_a.exists = True
        contact_b = MagicMock()
        contact_b.exists = True
        send_btn = MagicMock()
        send_btn.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "转发":
                return fwd_menu
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt3":
                return icon
            if kwargs.get("resourceId") == "com.tencent.wework:id/lt5":
                return done_btn
            if kwargs.get("text") == "A":
                return contact_a
            if kwargs.get("text") == "B":
                return contact_b
            if kwargs.get("textStartsWith") == "发送":
                # 兼顾 done_btn 与 send_btn 的 textStartsWith 命中
                return done_btn
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        missed = nav.forward_bubble_multi("商品A", ["A", "B"], scroll_up_max=0)
        assert missed == []
        # 长按气泡 + 点转发 + 勾 2 人 + 点完成
        mock_dev.long_click.assert_called_once()
        fwd_menu.click.assert_called_once()
        contact_a.click.assert_called_once()
        contact_b.click.assert_called_once()

    def test_partial_miss_returns_missed_list(self, nav, mock_dev):
        """B 找不到, 应返回 ['B']"""
        mock_dev.dump_hierarchy.return_value = FTA_XML

        fwd_menu = MagicMock()
        fwd_menu.exists = True
        icon = MagicMock()
        icon.exists = True
        done_btn = MagicMock()
        done_btn.exists = True
        contact_a = MagicMock()
        contact_a.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "转发":
                return fwd_menu
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt3":
                return icon
            if kwargs.get("resourceId") == "com.tencent.wework:id/lt5":
                return done_btn
            if kwargs.get("text") == "A":
                return contact_a
            if kwargs.get("textStartsWith") == "发送":
                return done_btn
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        missed = nav.forward_bubble_multi(
            "商品A", ["A", "B"], scroll_up_max=0
        )
        assert missed == ["B"]

    def test_all_missed_returns_all_and_backs_off(self, nav, mock_dev):
        """全部勾不上 → back 退出 → 返回全部 contacts"""
        mock_dev.dump_hierarchy.return_value = FTA_XML

        fwd_menu = MagicMock()
        fwd_menu.exists = True
        icon = MagicMock()
        icon.exists = True
        done_btn_only = MagicMock()
        done_btn_only.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "转发":
                return fwd_menu
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt3":
                return icon
            # 让 enter_multi_select_mode 感知到已进入
            if kwargs.get("resourceId") == "com.tencent.wework:id/lt5":
                return done_btn_only
            return _miss()

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        missed = nav.forward_bubble_multi(
            "商品A", ["X", "Y"], scroll_up_max=0
        )
        assert missed == ["X", "Y"]
        # 应触发过 back
        assert mock_dev.press.called

    def test_locator_not_found_raises(self, nav, mock_dev):
        """定位失败硬失败, 不返回 missed"""
        mock_dev.dump_hierarchy.return_value = (
            "<?xml version='1.0'?><hierarchy/>"
        )
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="未找到"):
            nav.forward_bubble_multi("不存在", ["A"], scroll_up_max=0)
