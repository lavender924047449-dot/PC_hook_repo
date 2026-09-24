"""PC 企微控件定位规则集中管理。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LocatorSet:
    main_window_name: str = "企业微信"
    main_window_regex: str = "企业微信|WeCom"
    # 企业微信主窗口的 Win32 class_name，用于在多窗口匹配时精确定位。
    # 设为空字符串可禁用此约束（仅凭标题匹配，兼容旧版本）。
    main_window_class: str = "WeWorkWindow"
    fta_keyword: str = "文件传输助手"
    search_box_names: tuple[str, ...] = ("搜索", "Search")
    message_input_names: tuple[str, ...] = ("输入", "发送消息", "消息输入框")
    forward_menu_names: tuple[str, ...] = ("转发", "Forward")
    confirm_send_names: tuple[str, ...] = ("发送", "确认")
    contact_result_list_names: tuple[str, ...] = ("搜索结果", "联系人", "会话")
    bubble_list_names: tuple[str, ...] = ("消息列表", "聊天记录")
    timeout_s: float = 8.0
    retry_count: int = 2
    ui_dump_dir: str = "spikes/pc_wecom_ui_dump"
    extra_notes: dict[str, str] = field(default_factory=dict)

    # ── 坐标定位参数（企微 Qt 渲染 UIA 失效时的兜底方案）────────────────────────
    # 企微 5.0.x 典型布局：左侧导航条(≈60px) + 联系人列表(≈260px) + 聊天区
    # 以下参数均可在 config.yaml 覆盖（通过 locators: 配置节）
    #
    # 聊天区域左边界（相对窗口宽度，0.0–1.0）
    chat_left_ratio: float = 0.22
    # 气泡横向点击位置（相对聊天区域宽度，偏右=自己发的消息在右侧）
    bubble_click_x_ratio: float = 0.75
    # 底部输入框高度（像素）
    input_area_height: int = 80
    # echo 编码文本气泡高度（像素）
    echo_bubble_height: int = 50
    # 从 echo 气泡上边界再向上偏移（像素），用于定位素材气泡中心
    material_bubble_offset: int = 100

    # ── 上下文菜单坐标参数（右键气泡后弹出的菜单）────────────────────────────
    # 企微 5.0.x FTA 场景（图片/文件气泡），菜单项典型顺序：
    #   0: 收藏  1: 转发  2: 复制  3: 引用  4: 删除  ...
    #
    # 菜单弹出位置相对右键点的水平偏移（菜单出现在右键点右侧）
    context_menu_dx: int = 10
    # 每个菜单项高度（像素）
    context_menu_item_height: int = 34
    # 菜单顶部内边距（第一个菜单项距菜单顶部的像素数）
    context_menu_top_padding: int = 8
    # "转发"/"Forward" 在菜单中的索引（从 0 起，默认第 2 项 = index 1）
    context_menu_forward_idx: int = 1


def default_locators() -> LocatorSet:
    return LocatorSet()

