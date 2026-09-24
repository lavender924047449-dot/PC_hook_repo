"""
Stage 4.5.5.2 WeComNavigator FTA 转发导航 单元测试.

使用 mock u2.Device, 不需要真机/模拟器.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from app.automation.navigator import (
    BubbleInfo,
    NavigationError,
    WeComNavigator,
)
from app.config import LocatorsConfig


# ======================== Fixtures ======================== #

SAMPLE_LOCATORS = LocatorsConfig(
    mic_toggle="com.tencent.wework:id/gif",
    hold_button="com.tencent.wework:id/ijs",
    input_edit="com.tencent.wework:id/iju",
    home_msg_tab_text="消息",
)

# 一个简化的 UI XML, 模拟 FTA 聊天中有 2 个 long-clickable 气泡
FTA_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node class="android.widget.FrameLayout" bounds="[0,0][720,1280]">
    <node class="androidx.recyclerview.widget.RecyclerView"
          bounds="[0,100][720,1100]" scrollable="true">
      <node class="android.widget.RelativeLayout"
            long-clickable="true" clickable="true"
            bounds="[50,200][670,350]"
            resource-id="" text="" content-desc="">
        <node class="android.widget.TextView"
              text="商品A 小程序" bounds="[60,210][400,260]" />
        <node class="android.widget.TextView"
              text="点击查看详情" bounds="[60,270][400,320]" />
      </node>
      <node class="android.widget.RelativeLayout"
            long-clickable="true" clickable="true"
            bounds="[50,400][670,550]"
            resource-id="" text="" content-desc="">
        <node class="android.widget.TextView"
              text="北京市朝阳区" bounds="[60,410][400,460]" />
        <node class="android.widget.TextView"
              text="位置信息" bounds="[60,470][400,520]" />
      </node>
    </node>
  </node>
</hierarchy>
"""

# 没有 long-clickable 节点的空 XML
EMPTY_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node class="android.widget.FrameLayout" bounds="[0,0][720,1280]">
    <node class="androidx.recyclerview.widget.RecyclerView"
          bounds="[0,100][720,1100]" scrollable="true">
    </node>
  </node>
</hierarchy>
"""


@pytest.fixture
def mock_dev():
    """创建 mock u2.Device"""
    dev = MagicMock()
    dev.info = {"displayWidth": 720, "displayHeight": 1280}
    return dev


@pytest.fixture
def nav(mock_dev):
    """创建 WeComNavigator 实例"""
    return WeComNavigator(mock_dev, SAMPLE_LOCATORS)


# ======================== BubbleInfo ======================== #


class TestBubbleInfo:
    def test_named_tuple_fields(self):
        b = BubbleInfo(
            cx=100, cy=200,
            bounds=(50, 150, 150, 250),
            text="hello", content_desc="", resource_id="", cls="View",
        )
        assert b.cx == 100
        assert b.cy == 200
        assert b.text == "hello"
        assert b.bounds == (50, 150, 150, 250)


# ======================== enumerate_fta_bubbles ======================== #


class TestEnumerateFtaBubbles:
    def test_finds_two_bubbles(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = FTA_XML
        bubbles = nav.enumerate_fta_bubbles()
        assert len(bubbles) == 2

    def test_bubbles_sorted_by_y(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = FTA_XML
        bubbles = nav.enumerate_fta_bubbles()
        assert bubbles[0].cy < bubbles[1].cy

    def test_text_includes_children(self, nav, mock_dev):
        """增强版: 应拼接子节点 text"""
        mock_dev.dump_hierarchy.return_value = FTA_XML
        bubbles = nav.enumerate_fta_bubbles()
        assert "商品A 小程序" in bubbles[0].text
        assert "点击查看详情" in bubbles[0].text

    def test_empty_chat_returns_empty(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = EMPTY_XML
        bubbles = nav.enumerate_fta_bubbles()
        assert bubbles == []

    def test_dump_hierarchy_error_raises(self, nav, mock_dev):
        mock_dev.dump_hierarchy.side_effect = Exception("connection lost")
        with pytest.raises(NavigationError, match="dump_hierarchy"):
            nav.enumerate_fta_bubbles()


# ======================== find_bubble_by_locator ======================== #


class TestFindBubbleByLocator:
    def test_finds_by_text_substring(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = FTA_XML
        b = nav.find_bubble_by_locator("商品A")
        assert "商品A 小程序" in b.text

    def test_finds_second_bubble(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = FTA_XML
        b = nav.find_bubble_by_locator("北京市")
        assert "北京市朝阳区" in b.text

    def test_not_found_raises(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = FTA_XML
        with pytest.raises(NavigationError, match="不存在的文本"):
            nav.find_bubble_by_locator("不存在的文本", scroll_up_max=0)

    def test_scrolls_up_on_miss(self, nav, mock_dev):
        """第一次枚举为空, 滚动后找到"""
        mock_dev.dump_hierarchy.side_effect = [EMPTY_XML, FTA_XML]
        b = nav.find_bubble_by_locator("商品A", scroll_up_max=1)
        assert "商品A" in b.text
        # 应调用过 swipe (向上滚动)
        mock_dev.swipe.assert_called_once()


# ======================== long_press_bubble ======================== #


class TestLongPressBubble:
    def test_calls_long_click(self, nav, mock_dev):
        nav.long_press_bubble(100, 200)
        mock_dev.long_click.assert_called_once_with(100, 200, duration=0.8)

    def test_custom_duration(self, nav, mock_dev):
        nav.long_press_bubble(50, 80, duration=1.2)
        mock_dev.long_click.assert_called_once_with(50, 80, duration=1.2)


# ======================== tap_forward_menu ======================== #


class TestTapForwardMenu:
    def test_clicks_forward(self, nav, mock_dev):
        fwd_el = MagicMock()
        fwd_el.exists = True

        def selector_side_effect(**kwargs):
            if kwargs.get("text") == "转发":
                return fwd_el
            m = MagicMock()
            m.exists = False
            return m

        mock_dev.side_effect = selector_side_effect
        mock_dev.__call__ = selector_side_effect
        nav.tap_forward_menu(timeout_s=0.5)
        fwd_el.click.assert_called_once()

    def test_not_found_raises(self, nav, mock_dev):
        miss = MagicMock()
        miss.exists = False
        mock_dev.return_value = miss
        mock_dev.dump_hierarchy.return_value = "<hierarchy/>"
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="转发"):
            nav.tap_forward_menu(timeout_s=0.3)


# ======================== pick_forward_target ======================== #


class TestPickForwardTarget:
    def test_direct_hit_in_recent_list(self, nav, mock_dev):
        """最近列表中直接命中"""
        contact_el = MagicMock()
        contact_el.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "张三":
                return contact_el
            m = MagicMock()
            m.exists = False
            return m

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.pick_forward_target("张三")
        contact_el.click.assert_called_once()

    def test_search_fallback(self, nav, mock_dev):
        """最近列表未命中, 搜索后命中"""
        contact_el = MagicMock()
        contact_el.exists = True

        search_icon = MagicMock()
        search_icon.exists = True

        edit_el = MagicMock()
        edit_el.exists = True

        # send_keys 被调用后才能"找到"联系人
        sent = {"done": False}

        def sel(**kwargs):
            if kwargs.get("text") == "李四":
                if sent["done"]:
                    return contact_el
                m = MagicMock()
                m.exists = False
                return m
            if kwargs.get("textContains") == "李四":
                if sent["done"]:
                    return contact_el
                m = MagicMock()
                m.exists = False
                return m
            if kwargs.get("resourceId") == "com.tencent.wework:id/nt8":
                return search_icon
            if kwargs.get("className") == "android.widget.EditText":
                return edit_el
            m = MagicMock()
            m.exists = False
            return m

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel

        original_send_keys = mock_dev.send_keys
        def fake_send_keys(text):
            sent["done"] = True
            return original_send_keys(text)
        mock_dev.send_keys = fake_send_keys

        nav.pick_forward_target("李四")
        contact_el.click.assert_called()


# ======================== confirm_forward_send ======================== #


class TestConfirmForwardSend:
    def test_clicks_send(self, nav, mock_dev):
        send_el = MagicMock()
        send_el.exists = True

        def sel(**kwargs):
            if kwargs.get("textStartsWith") == "发送":
                return send_el
            m = MagicMock()
            m.exists = False
            return m

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.confirm_forward_send(timeout_s=0.5)
        send_el.click.assert_called_once()

    def test_no_dialog_does_not_raise(self, nav, mock_dev):
        """没有二次确认弹窗也不应报错"""
        miss = MagicMock()
        miss.exists = False
        mock_dev.return_value = miss
        nav.confirm_forward_send(timeout_s=0.3)


# ======================== forward_bubble_to (组合) ======================== #


class TestForwardBubbleTo:
    def test_full_flow(self, nav, mock_dev):
        """完整链路: 定位→长按→转发→选人→确认"""
        mock_dev.dump_hierarchy.return_value = FTA_XML

        fwd_el = MagicMock()
        fwd_el.exists = True
        send_el = MagicMock()
        send_el.exists = True
        contact_el = MagicMock()
        contact_el.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "转发":
                return fwd_el
            if kwargs.get("text") == "张三":
                return contact_el
            if kwargs.get("textStartsWith") == "发送":
                return send_el
            m = MagicMock()
            m.exists = False
            return m

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.forward_bubble_to("商品A", "张三", scroll_up_max=0)

        mock_dev.long_click.assert_called_once()
        fwd_el.click.assert_called_once()
        contact_el.click.assert_called()
        send_el.click.assert_called()

    def test_locator_not_found_raises(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = EMPTY_XML
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="未找到"):
            nav.forward_bubble_to("不存在", "张三", scroll_up_max=0)


# ======================== open_fta ======================== #


class TestOpenFta:
    def test_calls_goto_home_and_open_chat(self, nav, mock_dev):
        """open_fta 应调用 goto_home + open_chat"""
        home_el = MagicMock()
        home_el.exists = True
        home_el.info = {"selected": True}

        fta_el = MagicMock()
        fta_el.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "消息":
                return home_el
            if kwargs.get("text") == "文件传输助手":
                return fta_el
            if kwargs.get("textContains") == "文件传输助手":
                return fta_el
            m = MagicMock()
            m.exists = False
            return m

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.open_fta()
        fta_el.click.assert_called()


# ======================== _collect_text (静态方法) ======================== #


class TestForwardToSelf:
    """Stage 4.5.5.4: forward_to_self 保鲜"""

    def test_forwards_to_fta_name(self, nav, mock_dev):
        """forward_to_self 应转发目标=FTA_NAME"""
        mock_dev.dump_hierarchy.return_value = FTA_XML

        fwd_el = MagicMock()
        fwd_el.exists = True
        contact_el = MagicMock()
        contact_el.exists = True
        send_el = MagicMock()
        send_el.exists = True

        def sel(**kwargs):
            if kwargs.get("text") == "转发":
                return fwd_el
            if kwargs.get("text") == "文件传输助手":
                return contact_el
            if kwargs.get("textContains") == "文件传输助手":
                return contact_el
            if kwargs.get("textStartsWith") == "发送":
                return send_el
            m = MagicMock()
            m.exists = False
            return m

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        nav.forward_to_self("商品A", scroll_up_max=0)

        # 应长按气泡 + 点转发 + 选 FTA + 确认
        mock_dev.long_click.assert_called_once()
        fwd_el.click.assert_called_once()
        contact_el.click.assert_called()  # 选人=FTA 自己
        send_el.click.assert_called()

    def test_locator_not_found_raises(self, nav, mock_dev):
        mock_dev.dump_hierarchy.return_value = EMPTY_XML
        mock_dev.screenshot = MagicMock()
        with pytest.raises(NavigationError, match="未找到"):
            nav.forward_to_self("不存在的素材", scroll_up_max=0)

    def test_does_not_open_fta_itself(self, nav, mock_dev):
        """forward_to_self 不应自己 open_fta (由调用方保证已在 FTA)"""
        mock_dev.dump_hierarchy.return_value = FTA_XML

        # 让所有 selector 命中, 避免其他步骤失败
        el = MagicMock()
        el.exists = True

        def sel(**kwargs):
            return el

        mock_dev.__call__ = sel
        mock_dev.side_effect = sel
        # goto_home 用到的 "消息" 也会命中 el.info; 需正常
        el.info = {"selected": True, "bounds": {"left": 0, "top": 0, "right": 100, "bottom": 100}}
        nav.forward_to_self("商品A", scroll_up_max=0)

        # 不应触发 goto_home 里的 press("back")
        mock_dev.press.assert_not_called()


class TestCollectText:
    def test_concatenates_child_text(self):
        import xml.etree.ElementTree as ET
        xml = '<node text="hello"><node text="world" /><node text="" /></node>'
        node = ET.fromstring(xml)
        result = WeComNavigator._collect_text(node)
        assert "hello" in result
        assert "world" in result

    def test_empty_tree(self):
        import xml.etree.ElementTree as ET
        xml = '<node text=""><node text="" /></node>'
        node = ET.fromstring(xml)
        result = WeComNavigator._collect_text(node)
        assert result == ""
