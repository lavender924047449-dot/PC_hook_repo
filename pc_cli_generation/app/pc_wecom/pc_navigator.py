"""
PC 企微导航封装（UIA 主 + pywinauto 辅）。

实现目标：
1) 对外暴露稳定的业务动作接口；
2) 每个动作都做前后状态校验；
3) 超时失败时自动产出 UI dump，便于现场定位。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from loguru import logger

from app.config import resolve_path
from app.pc_wecom.locators import LocatorSet, default_locators

try:  # pragma: no cover - 环境相关导入
    from pywinauto import Application
except Exception:  # pragma: no cover
    Application = None  # type: ignore[assignment]

try:  # pragma: no cover - 剪贴板支持（用于中文文本输入）
    import win32clipboard
    import win32con as _win32con
    _HAS_WIN32CLIP = True
except Exception:  # pragma: no cover
    _HAS_WIN32CLIP = False

try:  # pragma: no cover - 鼠标点击支持（用于激活输入框）
    import win32gui as _win32gui
    import win32api as _win32api
    _HAS_WIN32GUI = True
except Exception:  # pragma: no cover
    _HAS_WIN32GUI = False


class NavigatorTimeout(RuntimeError):
    pass


@dataclass(frozen=True)
class BubbleAnchor:
    material_code: str
    bubble_timestamp: str | None = None
    echo_message_id: str | None = None
    fingerprint_snippet: str | None = None
    # v2 (2026-09-10): 来自进程内存的精确锚点
    send_time_ms: int = 0      # 消息发送时间（Unix 毫秒，0=未获取）
    sequence: int = 0          # 会话内序列号（0=未获取）
    # v3 (2026-09-11 第十五轮): SQLite bind hook 抓到的真实 per-message msgid
    # （原本存于 anchor.wecom_message_id 但从未传入 BubbleAnchor；本轮打通链路）
    # 0 表示未取到，走时间/坐标兜底
    wecom_message_id: int = 0


class NavigatorBackend(Protocol):
    def ensure_window(self, locators: LocatorSet) -> bool: ...
    def focus_chat(self, chat_name: str, locators: LocatorSet) -> bool: ...
    def send_text(self, text: str, locators: LocatorSet) -> bool: ...
    def right_click_bubble(self, anchor: BubbleAnchor, locators: LocatorSet) -> bool: ...
    def click_menu(self, names: tuple[str, ...], locators: LocatorSet | None = None) -> bool: ...
    def pick_contact(self, keyword: str, locators: LocatorSet) -> bool: ...
    def dump_tree(self) -> str: ...


class NullBackend:
    """无 UI 库时的兜底实现，便于离线测试。"""

    def __init__(self) -> None:
        self.running = True
        self.current_chat = ""
        self.logs: list[str] = []

    def ensure_window(self, locators: LocatorSet) -> bool:
        self.logs.append(f"ensure_window:{locators.main_window_name}")
        return self.running

    def focus_chat(self, chat_name: str, locators: LocatorSet) -> bool:
        self.current_chat = chat_name.strip()
        self.logs.append(f"focus_chat:{self.current_chat}")
        return bool(self.current_chat)

    def send_text(self, text: str, locators: LocatorSet) -> bool:
        self.logs.append(f"send_text:{text}")
        return bool(self.current_chat and text.strip())

    def right_click_bubble(self, anchor: BubbleAnchor, locators: LocatorSet) -> bool:
        self.logs.append(f"right_click_bubble:{anchor.material_code}")
        return bool(anchor.material_code.strip())

    def click_menu(self, names: tuple[str, ...], locators: LocatorSet | None = None) -> bool:
        self.logs.append(f"click_menu:{'|'.join(names)}")
        return True

    def pick_contact(self, keyword: str, locators: LocatorSet) -> bool:
        self.logs.append(f"pick_contact:{keyword}")
        return bool(keyword.strip())

    def dump_tree(self) -> str:
        return "\n".join(self.logs)


class PyWinAutoBackend:
    """
    轻量 pywinauto 后端。

    注意：企微版本差异较大，本实现采用候选名和弱约束查找，
    首要目标是“可诊断、可迭代”，而不是一次覆盖所有皮肤版本。
    """

    def __init__(self) -> None:
        self._app = None
        self._win = None
        # 最近一次 Win32 坐标右键的屏幕坐标（供 click_menu 坐标兜底使用）
        self._last_right_click_pos: tuple[int, int] | None = None

    def ensure_window(self, locators: LocatorSet) -> bool:
        if Application is None:
            logger.error(
                "pywinauto 未安装或导入失败，无法操作企业微信界面。"
                "请使用项目 .venv 中的 Python 运行：.venv\\Scripts\\python.exe main.py ..."
            )
            return False
        # 使用 class_name='WeWorkWindow' 精确定位企业微信主窗口，
        # 避免浏览器等标题中包含"企业微信"关键词的窗口造成多匹配歧义错误。
        connect_kwargs: dict = {"title_re": locators.main_window_regex, "timeout": 3}
        if locators.main_window_class:
            connect_kwargs["class_name"] = locators.main_window_class
        win_kwargs: dict = {"title_re": locators.main_window_regex}
        if locators.main_window_class:
            win_kwargs["class_name"] = locators.main_window_class
        try:
            self._app = Application(backend="uia").connect(**connect_kwargs)
            self._win = self._app.window(**win_kwargs)
            self._win.set_focus()
            return True
        except Exception:
            return False

    def focus_chat(self, chat_name: str, locators: LocatorSet) -> bool:
        if self._win is None:
            return False
        # 优先：通过 UIA Edit 控件定位搜索框
        box = self._find_edit(locators.search_box_names)
        if box is not None:
            box.set_edit_text("")
            box.type_keys(chat_name, with_spaces=True, set_foreground=True)
            time.sleep(0.2)
            box.type_keys("{ENTER}")
            return True
        # 兜底：企业微信使用 Qt 自定义渲染，无标准 Edit 控件暴露。
        # 用 Ctrl+F 打开全局搜索，再通过剪贴板粘贴会话名，最后 Enter 确认。
        logger.debug("未找到 UIA Edit，回退到 Ctrl+F + 剪贴板方式定位会话")
        self._win.set_focus()
        time.sleep(0.2)
        self._win.type_keys("^f", set_foreground=True)  # 企微全局搜索
        time.sleep(0.5)
        # 清空搜索框并粘贴会话名
        self._win.type_keys("^a")
        self._clipboard_paste(chat_name)
        time.sleep(0.4)
        self._win.type_keys("{ENTER}")  # 跳转到搜索结果
        time.sleep(0.4)
        self._win.type_keys("{ENTER}")  # 确认进入会话
        return True

    def send_text(self, text: str, locators: LocatorSet) -> bool:
        if self._win is None:
            return False
        # 优先：通过 UIA Edit 控件定位输入框
        box = self._find_edit(locators.message_input_names)
        if box is not None:
            box.set_edit_text(text)
            box.type_keys("{ENTER}")
            return True
        # 兜底：用剪贴板粘贴文本，避免中文字符 type_keys 乱码问题。
        # 企业微信使用 Qt 自定义渲染，set_focus() 只激活主窗口，
        # 输入框本身不会自动获得焦点，需先点击输入框区域再粘贴。
        logger.debug("未找到 UIA Edit，回退到「点击输入框区域 + 剪贴板粘贴」方式发送文本")
        self._win.set_focus()
        time.sleep(0.3)
        self._click_input_area()  # 点击窗口底部中央（输入框所在位置）
        time.sleep(0.3)
        self._clipboard_paste(text)
        time.sleep(0.2)
        self._win.type_keys("{ENTER}")
        return True

    def _click_input_area(self) -> None:
        """
        点击企业微信聊天输入框区域，使其获得键盘焦点。
        企微的输入框位于窗口底部约 88% 处，水平居中。
        使用 win32api 模拟鼠标左键点击；不可用时静默忽略。
        """
        if not _HAS_WIN32GUI or self._win is None:
            return
        try:
            hwnd = self._win.handle
            left, top, right, bottom = _win32gui.GetWindowRect(hwnd)
            cx = (left + right) // 2
            # 输入框在窗口高度 88% 处（可根据实际界面微调）
            cy = top + int((bottom - top) * 0.88)
            # 移动鼠标并点击
            _win32api.SetCursorPos((cx, cy))
            time.sleep(0.05)
            _win32api.mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
            time.sleep(0.05)
            _win32api.mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
            logger.debug(f"已点击输入框区域: ({cx}, {cy})")
        except Exception as e:
            logger.debug(f"点击输入框区域失败（忽略）: {e}")

    def _clipboard_paste(self, text: str) -> None:
        """将文本写入剪贴板后向窗口发送 Ctrl+V。优先 win32clipboard，无则 tkinter。"""
        pasted = False
        if _HAS_WIN32CLIP:
            try:
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(text, _win32con.CF_UNICODETEXT)
                win32clipboard.CloseClipboard()
                pasted = True
            except Exception as e:
                logger.debug(f"win32clipboard 写入失败: {e}")
        if not pasted:
            try:
                import tkinter as tk
                r = tk.Tk()
                r.withdraw()
                r.clipboard_clear()
                r.clipboard_append(text)
                r.update()
                r.destroy()
                pasted = True
            except Exception as e:
                logger.debug(f"tkinter 剪贴板写入失败: {e}")
        if pasted and self._win is not None:
            self._win.type_keys("^v", set_foreground=True)

    def right_click_bubble(self, anchor: BubbleAnchor, locators: LocatorSet) -> bool:
        """三阶段定位气泡并右键：UIA指纹 → UIA时间文本 → Win32坐标估算。

        企微 5.0.x 使用 Qt 自绘，UIA 树通常为空（<hierarchy/>），因此
        Phase 1/2 大概率失败；Phase 3 坐标兜底是当前最可靠路径。
        """
        if self._win is None:
            return False
        keyword = anchor.fingerprint_snippet or anchor.material_code

        # ── Phase 0: 真实 wecom_message_id 精确匹配（第十五轮新增）──────────
        # 来源：SQLite bind hook（`NativeMsgIdReader`），已在 BubbleAnchorService
        # v3 中把会话级 `193405740` 覆写为每消息真实 msgid。
        # 若企微 UIA 树暴露了含 msgid 的属性（AutomationId/Name/HelpText/
        # RuntimeId），此处一次命中即可精确定位，避免 P3 坐标估算的漂移。
        if anchor.wecom_message_id > 0:
            if self._right_click_by_msgid(anchor.wecom_message_id):
                logger.debug(
                    f"[气泡定位 P0-msgid] 成功: msgid={anchor.wecom_message_id}"
                )
                return True

        # ── Phase 1: UIA 指纹文本匹配（保留以兼容未来企微版本）─────────────
        try:
            node = self._win.child_window(
                title_re=f".*{keyword}.*", control_type="Text"
            )
            node.wrapper_object().right_click_input()
            logger.debug(f"[气泡定位 P1-UIA指纹] 成功: {keyword!r}")
            return True
        except Exception:
            pass

        # ── Phase 2: UIA 时间文本匹配（send_time_ms → 本地 HH:MM）─────────
        if anchor.send_time_ms > 0:
            try:
                from datetime import datetime as _dt
                dt_local = _dt.fromtimestamp(anchor.send_time_ms / 1000)
                for time_str in (
                    dt_local.strftime("%H:%M"),
                    dt_local.strftime("%H:%M:%S"),
                    # Windows strftime 不支持 %-H，手动去掉前导零
                    dt_local.strftime("%H:%M").lstrip("0") or "0:00",
                ):
                    try:
                        node = self._win.child_window(
                            title_re=f".*{time_str}.*", control_type="Text"
                        )
                        node.wrapper_object().right_click_input()
                        logger.debug(f"[气泡定位 P2-UIA时间] 成功: {time_str!r}")
                        return True
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"[气泡定位 P2-UIA时间] 异常: {e}")

        # ── Phase 3: Win32 坐标估算右键（兜底主路径）───────────────────────
        if _HAS_WIN32GUI:
            try:
                if self._right_click_coordinate(anchor, locators):
                    logger.debug("[气泡定位 P3-坐标] 右键已发送")
                    return True
            except Exception as e:
                logger.debug(f"[气泡定位 P3-坐标] 失败: {e}")

        return False

    def _right_click_by_msgid(self, msgid: int) -> bool:
        """按真实 wecom_message_id 在 UIA 树中查找并右键素材气泡。

        企微 Qt 自绘 UIA 树在 5.0.x 通常极度精简（多为空），但个别构建里
        AutomationId 会带 message_id 数字或包含它的字符串。本函数按以下顺序尝试
        （任一命中即右键返回 True）：

          1. `AutomationId == str(msgid)` 精确
          2. `AutomationId` / `Name` 包含 str(msgid)（通配 `.*msgid.*`）
          3. 遍历所有可读的 descendant，检查其
             `automation_id` / `window_text` / `help_text` 中是否含 msgid 子串

        为避免全树遍历超时，descendant 扫描裁剪到前 600 个节点（与
        `dump_tree` 一致）。任何异常都被吞掉视作未命中，交给 P1/P2/P3 兜底。
        """
        if self._win is None or msgid <= 0:
            return False
        mid_str = str(int(msgid))

        def _try_right_click(ctrl) -> bool:
            try:
                ctrl.right_click_input()
            except Exception:
                return False
            # 记录当前光标位置，供 click_menu P3 坐标兜底使用
            self._remember_cursor_pos()
            return True

        # 路径 A：AutomationId 精确 / 通配匹配
        for kwargs in (
            {"auto_id": mid_str},
            {"auto_id": mid_str, "control_type": "Text"},
            {"auto_id": mid_str, "control_type": "ListItem"},
            {"auto_id_re": f".*{mid_str}.*"},
            {"title_re": f".*{mid_str}.*"},
        ):
            try:
                node = self._win.child_window(**kwargs)
                wrapper = node.wrapper_object()
            except Exception:
                continue
            if _try_right_click(wrapper):
                return True

        # 路径 B：全 descendant 扫描（最后手段，代价大但覆盖率最高）
        try:
            descendants = self._win.descendants()
        except Exception:
            return False
        for ctrl in descendants[:600]:
            try:
                elem = ctrl.element_info
                fields = (
                    str(getattr(elem, "automation_id", "") or ""),
                    str(getattr(ctrl, "window_text", lambda: "")() or ""),
                    str(getattr(elem, "help_text", "") or ""),
                )
            except Exception:
                continue
            if not any(mid_str in f for f in fields):
                continue
            if _try_right_click(ctrl):
                return True
        return False

    def _remember_cursor_pos(self) -> None:
        """把当前鼠标屏幕坐标记入 `_last_right_click_pos`（供 click_menu P3 使用）。"""
        if not _HAS_WIN32GUI:
            return
        try:
            self._last_right_click_pos = _win32api.GetCursorPos()  # type: ignore[assignment]
        except Exception:
            pass

    def _right_click_coordinate(
        self, anchor: BubbleAnchor, locators: LocatorSet
    ) -> bool:
        """基于窗口坐标估算，右键点击素材气泡（企微 Qt 渲染 UIA 失效的兜底方案）。

        布局假设（企微 5.0.x FTA 场景，已进入聊天并滚动至底部）：
            bottom - input_area_height            → 输入框上边界
            bottom - input_area_height - echo_h   → echo 编码文本气泡上边界
            以上再向上 material_bubble_offset px  → 素材气泡大致中心

        所有偏移量均可通过 LocatorSet 调整。
        """
        hwnd = self._win.handle
        left, top, right, bottom = _win32gui.GetWindowRect(hwnd)
        w = right - left
        h = bottom - top

        # 聊天内容区左边界（排除左侧导航 + 联系人列表面板）
        chat_left = left + int(w * locators.chat_left_ratio)
        chat_right = right - 4

        # 步骤 1：激活窗口并让聊天区域获得键盘焦点
        self._win.set_focus()
        time.sleep(0.15)
        # 点击聊天区域中间，确保键盘焦点在聊天列表（而非搜索框等）
        focus_x = (chat_left + chat_right) // 2
        focus_y = top + int(h * 0.45)
        _win32api.SetCursorPos((focus_x, focus_y))
        time.sleep(0.05)
        _win32api.mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
        time.sleep(0.03)
        _win32api.mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
        time.sleep(0.12)

        # 步骤 2：按 End 键滚动到聊天底部（确保最新素材气泡可见）
        self._win.type_keys("{END}", set_foreground=True)
        time.sleep(0.35)

        # 步骤 3：计算素材气泡的估算坐标
        #   horizontal: 聊天区域偏右（自己发的消息在右侧气泡）
        #   vertical:   从窗口底部往上 = 输入框 + echo气泡高度 + 额外偏移
        cx = chat_left + int((chat_right - chat_left) * locators.bubble_click_x_ratio)
        cy = (
            bottom
            - locators.input_area_height
            - locators.echo_bubble_height
            - locators.material_bubble_offset
        )
        # 安全夹紧（不超出窗口边界）
        cy = max(top + 60, min(cy, bottom - locators.input_area_height - 20))

        logger.debug(
            f"[坐标右键] 窗口({w}×{h}) "
            f"chat_left={chat_left} 点击({cx},{cy}) "
            f"send_time_ms={anchor.send_time_ms}"
        )

        # 步骤 4：移动鼠标并发送右键点击
        _win32api.SetCursorPos((cx, cy))
        time.sleep(0.10)
        _win32api.mouse_event(0x0008, 0, 0, 0, 0)  # MOUSEEVENTF_RIGHTDOWN
        time.sleep(0.05)
        _win32api.mouse_event(0x0010, 0, 0, 0, 0)  # MOUSEEVENTF_RIGHTUP
        time.sleep(0.30)  # 等待上下文菜单出现
        # 记录右键位置，供 click_menu 坐标兜底使用
        self._last_right_click_pos = (cx, cy)
        return True

    def click_menu(self, names: tuple[str, ...], locators: LocatorSet | None = None) -> bool:
        """三阶段点击上下文菜单项：UIA主窗口 → UIA Desktop根 → Win32坐标估算。

        企微 5.0.x 上下文菜单在 UIA 树中可能不可见（Qt 渲染），
        但 pywinauto Desktop 根搜索有时能找到弹出层。
        最终兜底：按右键坐标 + 菜单项索引估算位置并点击。
        """
        # ── Phase 1: UIA 主窗口子树搜索（速度快）─────────────────────────────
        if self._win is not None:
            for n in names:
                try:
                    menu = self._win.child_window(title=n, control_type="MenuItem")
                    menu.wrapper_object().click_input()
                    logger.debug(f"[click_menu P1-主窗口UIA] 成功: {n!r}")
                    return True
                except Exception:
                    continue

        # ── Phase 2: UIA Desktop 根搜索（上下文菜单为顶层窗口时有效）──────────
        # 注意：必须使用极短超时，否则搜索 15s+ 会导致上下文菜单自动关闭。
        try:
            from pywinauto import Desktop as _Desktop
            from pywinauto import timings as _timings
            # Fast 模式：所有 pywinauto 超时设为 0（立即失败而非等待）
            _timings.Timings.fast()
            try:
                desktop = _Desktop(backend="uia")
                for n in names:
                    try:
                        item = desktop.window(title=n, control_type="MenuItem")
                        item.wrapper_object().click_input()
                        logger.debug(f"[click_menu P2-Desktop UIA] 成功: {n!r}")
                        return True
                    except Exception:
                        continue
            finally:
                _timings.Timings.defaults()  # 恢复默认超时
        except Exception as e:
            logger.debug(f"[click_menu P2-Desktop UIA] 异常: {e}")

        # ── Phase 3: Win32 坐标估算点击（兜底）──────────────────────────────
        if _HAS_WIN32GUI and self._last_right_click_pos and locators is not None:
            try:
                if self._click_menu_coordinate(names, locators):
                    return True
            except Exception as e:
                logger.debug(f"[click_menu P3-坐标] 失败: {e}")

        return False

    def _click_menu_coordinate(
        self,
        names: tuple[str, ...],
        locators: LocatorSet,
    ) -> bool:
        """基于右键点击坐标估算，点击上下文菜单项。

        菜单布局假设（企微 5.0.x FTA 图片/文件气泡右键）：
          Item 0: 收藏
          Item 1: 转发   ← context_menu_forward_idx=1
          Item 2: 复制
          Item 3: 引用
          Item 4: 删除

        菜单弹出在右键点的右下方，顶部内边距约 8px，每项约 34px。
        可通过 LocatorSet 调整。
        """
        assert self._last_right_click_pos is not None
        rx, ry = self._last_right_click_pos

        # 映射各 names 到已知菜单索引（仅支持转发场景；其他场景走前两阶段）
        _NAME_TO_IDX: dict[str, int] = {
            "转发": locators.context_menu_forward_idx,
            "Forward": locators.context_menu_forward_idx,
            # 发送/确认按钮通常在选人弹窗，不走此路径
        }

        for n in names:
            idx = _NAME_TO_IDX.get(n, -1)
            if idx < 0:
                continue
            # 菜单项中心坐标
            mx = rx + locators.context_menu_dx + 80  # 菜单项水平中心
            my = (
                ry
                + locators.context_menu_top_padding
                + idx * locators.context_menu_item_height
                + locators.context_menu_item_height // 2
            )
            logger.debug(
                f"[click_menu P3-坐标] 点击 {n!r} "
                f"右键点=({rx},{ry}) 菜单项=({mx},{my})"
            )
            _win32api.SetCursorPos((mx, my))
            time.sleep(0.08)
            _win32api.mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
            time.sleep(0.05)
            _win32api.mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
            time.sleep(0.30)  # 等待选人弹窗打开
            return True

        return False

    def pick_contact(self, keyword: str, locators: LocatorSet) -> bool:
        if self._win is None:
            return False
        box = self._find_edit(locators.search_box_names)
        if box is None:
            return False
        box.set_edit_text("")
        box.type_keys(keyword, with_spaces=True, set_foreground=True)
        time.sleep(0.2)
        box.type_keys("{ENTER}")
        return True

    def dump_tree(self) -> str:
        if self._win is None:
            return "(window not attached)"
        rows = []
        try:
            descendants = self._win.descendants()
        except Exception:
            return "(dump failed)"
        for idx, ctrl in enumerate(descendants[:600]):
            try:
                rows.append(
                    {
                        "idx": idx,
                        "name": ctrl.window_text(),
                        "class": ctrl.friendly_class_name(),
                        "auto_id": getattr(ctrl.element_info, "automation_id", ""),
                        "type": getattr(ctrl.element_info, "control_type", ""),
                    }
                )
            except Exception:
                continue
        return json.dumps(rows, ensure_ascii=False, indent=2)

    def _find_edit(self, candidates: tuple[str, ...]):
        if self._win is None:
            return None
        for n in candidates:
            try:
                obj = self._win.child_window(title=n, control_type="Edit")
                return obj.wrapper_object()
            except Exception:
                continue
        try:
            return self._win.child_window(control_type="Edit").wrapper_object()
        except Exception:
            return None


class PCWeComNavigator:
    def __init__(
        self,
        *,
        locators: LocatorSet | None = None,
        backend: NavigatorBackend | None = None,
    ) -> None:
        self.locators = locators or default_locators()
        self._backend = backend or PyWinAutoBackend()
        self._focused_chat: str | None = None

    def ensure_running(self) -> None:
        ok = self._retry(lambda: self._backend.ensure_window(self.locators), "无法连接企业微信主窗口")
        if not ok:
            self._dump_on_error("ensure_running")
            raise NavigatorTimeout("请先启动并登录 PC 企业微信")

    def open_fta(self) -> None:
        self.focus_chat(self.locators.fta_keyword)

    def focus_chat(self, name: str) -> None:
        self.ensure_running()
        n = name.strip()
        if not n:
            raise ValueError("会话名不能为空")
        ok = self._retry(lambda: self._backend.focus_chat(n, self.locators), f"无法定位会话: {n}")
        if not ok:
            self._dump_on_error("focus_chat")
            raise NavigatorTimeout(f"打开会话失败: {n}")
        self._focused_chat = n
        logger.debug(f"focus_chat -> {n}")

    def send_text(self, text: str) -> None:
        self.ensure_running()
        if not self._focused_chat:
            raise RuntimeError("未聚焦会话，无法发送文本")
        payload = text.strip()
        if not payload:
            raise ValueError("发送文本不能为空")
        ok = self._retry(lambda: self._backend.send_text(payload, self.locators), "发送文本失败")
        if not ok:
            self._dump_on_error("send_text")
            raise NavigatorTimeout("发送文本失败，请检查输入框定位")

    def send_text_to_active_window(self, text: str) -> None:
        """
        直接向当前已聚焦的企业微信窗口发送文本，无需搜索/切换会话。

        适用场景：用户刚向 FTA 发完文件，企业微信本身已停留在 FTA
        聊天界面，程序只需激活窗口并粘贴编码即可，无需再导航。
        """
        self.ensure_running()
        payload = text.strip()
        if not payload:
            raise ValueError("发送文本不能为空")
        ok = self._retry(lambda: self._backend.send_text(payload, self.locators), "发送文本失败")
        if not ok:
            self._dump_on_error("send_text")
            raise NavigatorTimeout("发送文本失败，请检查输入框定位")

    def long_press_bubble(self, anchor: BubbleAnchor) -> None:
        self.ensure_running()
        ok = self._retry(lambda: self._backend.right_click_bubble(anchor, self.locators), "定位气泡失败")
        if not ok:
            self._dump_on_error("long_press_bubble")
            raise NavigatorTimeout(f"未找到目标气泡: {anchor.material_code}")

    def pick_forward_menu(self) -> None:
        self.ensure_running()
        ok = self._retry(
            lambda: self._backend.click_menu(self.locators.forward_menu_names, self.locators),
            "点击转发菜单失败",
        )
        if not ok:
            self._dump_on_error("pick_forward_menu")
            raise NavigatorTimeout("未找到“转发”菜单")

    def search_and_pick_contact(self, keyword: str) -> bool:
        self.ensure_running()
        kw = keyword.strip()
        if not kw:
            return False
        ok = self._retry(lambda: self._backend.pick_contact(kw, self.locators), f"选择联系人失败: {kw}")
        if not ok:
            self._dump_on_error("search_and_pick_contact")
            return False
        return True

    def confirm_send(self) -> None:
        self.ensure_running()
        ok = self._retry(
            lambda: self._backend.click_menu(self.locators.confirm_send_names, self.locators),
            "点击发送失败",
        )
        if not ok:
            self._dump_on_error("confirm_send")
            raise NavigatorTimeout("未找到“发送/确认”按钮")

    def dump_ui_tree(self, reason: str = "manual") -> Path:
        dump_dir = resolve_path(self.locators.ui_dump_dir)
        dump_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = dump_dir / f"pc_wecom_{reason}_{ts}.json"
        fp.write_text(self._backend.dump_tree(), encoding="utf-8")
        logger.info(f"UI dump 已写入: {fp}")
        return fp

    def _retry(self, fn, err_msg: str) -> bool:
        attempts = max(1, self.locators.retry_count + 1)
        for i in range(attempts):
            if fn():
                return True
            if i < attempts - 1:
                time.sleep(0.25)
        logger.debug(err_msg)
        return False

    def _dump_on_error(self, reason: str) -> None:
        try:
            self.dump_ui_tree(reason=reason)
        except Exception as e:
            logger.debug(f"写 UI dump 失败（忽略）: {e}")
