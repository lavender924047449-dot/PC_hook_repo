"""
企微 (Android) 导航封装。

DEPRECATED: Android 链路已由 PC 企微 FTA 主链路取代，仅保留兼容。

负责：
    goto_home()           - 回到消息列表
    open_chat(name)       - 打开指定聊天 (先列表直点，未见则下拉搜索)
    enter_voice_mode()    - 切到语音输入模式
    button_center()       - 返回 [按住 说话] 按钮的中心坐标

Stage 4.5.5.2 新增 (FTA 转发导航):
    open_fta()                      - 打开文件传输助手聊天
    enumerate_fta_bubbles()         - 枚举 FTA 可长按气泡 (拼接子节点文本)
    find_bubble_by_locator(text)    - 按 fta_locator 文本定位气泡
    long_press_bubble(cx, cy)       - 长按指定坐标弹出上下文菜单
    tap_forward_menu()              - 点击上下文菜单中的"转发"
    pick_forward_target(contact)    - 单选选人界面: 最近列表直点 / 搜索
    confirm_forward_send()          - 二次确认弹窗点"发送"
    forward_bubble_to(locator, contact) - 组合: 定位→长按→转发→选人→确认

Stage 4.5.5.4 新增 (FTA 素材保鲜):
    forward_to_self(locator)        - 转发老气泡给"文件传输助手"本人,
                                       使其变成最新一条 (top_pinned 保鲜)

Stage 4.5.6 新增 (个人名片):
    open_contact_card_picker()      - "+"面板→"个人名片"→进入好友选择器
    pick_friend_for_card(name)      - 名片选择器里搜/点目标好友
    send_contact_card(friend_name)  - 组合: 打开面板→个人名片→选人→确认发送

Stage 4.5.7 新增 (FTA 多选群发):
    enter_multi_select_mode()       - 选人界面点右上多选图标 (勾选模式)
    tick_contact_in_multi_select(n) - 勾选一个联系人 (直点 / 搜索兜底)
    tap_multi_select_done()         - 点底部 "完成/发送(N)"
    forward_bubble_multi(locator, contacts) - 组合: 定位→长按→转发→多选→
                                              勾选→完成→确认; 返回未勾中列表

Stage 4.5.8 新增 (收藏表情):
    open_emoji_panel()              - 打开输入区 emoji 面板
    switch_to_favorite_stickers()   - 切到 "收藏" tab
    pick_sticker_by_locator(loc)    - 按 locator 语法定位并点击一张表情:
                                        "idx:N" / 纯数字 → 第 N 张
                                        "desc:XXX" → content-desc 子串匹配
    send_sticker(locator)           - 组合: 打开 emoji → 切收藏 → 点表情
"""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

import uiautomator2 as u2
from loguru import logger

from app.config import LocatorsConfig, resolve_path


class NavigationError(RuntimeError):
    pass


class BubbleInfo(NamedTuple):
    """FTA 气泡的结构化信息 (Stage 4.5.5.2)."""
    cx: int
    cy: int
    bounds: tuple[int, int, int, int]  # (left, top, right, bottom)
    text: str           # 拼接自身 + 子节点全部 text
    content_desc: str
    resource_id: str
    cls: str


class WeComNavigator:
    def __init__(self, dev: u2.Device, locators: LocatorsConfig) -> None:
        self.dev = dev
        self.loc = locators

    # ---------------- Home ---------------- #
    def goto_home(self, max_back: int = 5) -> None:
        """尽力回到消息列表 (通过 back / 点消息 tab)"""
        logger.debug("goto_home")
        home = self.dev(text=self.loc.home_msg_tab_text)
        for _ in range(max_back):
            if home.exists:
                if not home.info.get("selected", False):
                    home.click()
                    time.sleep(0.5)
                logger.debug("已在消息列表")
                return
            self.dev.press("back")
            time.sleep(0.3)
        # 兜底：再检查一次
        if not self.dev(text=self.loc.home_msg_tab_text).exists:
            logger.warning("可能不在消息列表，但继续尝试后续操作")

    # ---------------- Open chat ---------------- #
    def open_chat(self, name: str, timeout_s: float = 6.0) -> None:
        """打开指定名字的聊天。策略：先列表直点，未见则下拉调出搜索栏。"""
        logger.info(f"open_chat: {name!r}")
        if self._click_from_list(name):
            return
        logger.debug("列表未见，尝试下拉搜索")
        if not self._swipe_down_reveal_search():
            raise NavigationError("下拉后未发现搜索栏，请手动排查 UI")
        if not self._search_and_tap(name, timeout_s):
            raise NavigationError(f"搜索结果中未找到 {name!r}")

    def _click_from_list(self, name: str) -> bool:
        el = self.dev(text=name)
        if not el.exists:
            el = self.dev(textContains=name)
        if el.exists:
            el.click()
            time.sleep(1.2)
            return True
        return False

    def _swipe_down_reveal_search(self) -> bool:
        info = self.dev.info
        w = info["displayWidth"]
        h = info["displayHeight"]
        for factor in (0.7, 0.85):
            self.dev.swipe(w // 2, int(h * 0.30), w // 2, int(h * factor), duration=0.3)
            time.sleep(0.6)
            if self.dev(className="android.widget.EditText").exists:
                return True
        return False

    def _search_and_tap(self, name: str, timeout_s: float) -> bool:
        edit = self.dev(className="android.widget.EditText")
        if not edit.exists:
            return False
        edit.click()
        time.sleep(0.3)
        try:
            self.dev.clear_text()
        except Exception:
            pass
        self.dev.send_keys(name)
        time.sleep(1.2)

        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            for sel in (dict(text=name), dict(textContains=name)):
                el = self.dev(**sel)
                if el.exists:
                    el.click()
                    time.sleep(1.5)
                    return True
            time.sleep(0.3)
        return False

    # ---------------- Voice mode ---------------- #
    def enter_voice_mode(self, timeout_s: float = 5.0) -> None:
        """把输入区从"打字"切到"按住说话"。幂等：已是语音模式直接返回。"""
        if self.dev(resourceId=self.loc.hold_button).exists:
            logger.debug("已处于语音模式")
            return

        mic = self.dev(resourceId=self.loc.mic_toggle)
        if not mic.exists:
            raise NavigationError(
                f"找不到 mic 切换按钮 (resourceId={self.loc.mic_toggle})，"
                f"确认当前是否在聊天窗口"
            )
        mic.click()

        # 等 [按住 说话] 出现
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self.dev(resourceId=self.loc.hold_button).exists:
                logger.debug("已进入语音模式")
                return
            time.sleep(0.2)
        raise NavigationError("点击 mic 切换后仍未出现 [按住 说话] 按钮")

    # ---------------- Button coord ---------------- #
    def button_center(self) -> tuple[int, int]:
        """返回 [按住 说话] 按钮中心 (x, y)"""
        el = self.dev(resourceId=self.loc.hold_button)
        if not el.exists:
            raise NavigationError("[按住 说话] 按钮不存在，请先 enter_voice_mode()")
        b = el.info["bounds"]
        return ((b["left"] + b["right"]) // 2, (b["top"] + b["bottom"]) // 2)

    # ================================================================ #
    #                     Stage 4.5.2  文本输入                          #
    # ================================================================ #

    def enter_text_mode(self, timeout_s: float = 5.0) -> None:
        """
        把输入区从"按住说话"切到"文字输入". 幂等: 已是文字模式直接返回.
        与 enter_voice_mode 是同一个 mic_toggle 按钮的两个状态.
        """
        if self.dev(resourceId=self.loc.input_edit).exists:
            logger.debug("已处于文字输入模式")
            return

        mic = self.dev(resourceId=self.loc.mic_toggle)
        if not mic.exists:
            raise NavigationError(
                f"找不到 mic 切换按钮 (resourceId={self.loc.mic_toggle})"
            )
        mic.click()
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self.dev(resourceId=self.loc.input_edit).exists:
                logger.debug("已进入文字输入模式")
                return
            time.sleep(0.2)
        raise NavigationError("点击 mic 切换后仍未出现输入框")

    def type_text(self, text: str, *, clear: bool = True) -> None:
        """
        在当前聊天的输入框里输入文本. 假定已 enter_text_mode.
        使用 uiautomator2 的 IME 输入; 支持中文/emoji unicode.
        """
        edit = self.dev(resourceId=self.loc.input_edit)
        if not edit.exists:
            raise NavigationError("输入框不可见, 请先 enter_text_mode()")
        edit.click()
        time.sleep(0.25)
        if clear:
            try:
                self.dev.clear_text()
            except Exception as e:
                logger.debug(f"clear_text 失败, 忽略: {e}")
        # uiautomator2 会自动切换 FastInputIME (adb keyboard) 来避免中文丢字
        self.dev.send_keys(text)
        time.sleep(0.4)

    # ---- 发送按钮候选 (从最精确到最宽泛) ---- #
    # 顺序: 用户显式配置 → 常见 text=发送 → text 前缀
    _SEND_TEXT_CANDIDATES: tuple[dict, ...] = (
        dict(text="发送"),
        dict(textStartsWith="发送"),
        dict(description="发送"),
    )

    # ================================================================ #
    #                     Stage 4.5.3  相册 / 附件面板                    #
    # ================================================================ #

    #: "+" 附件面板打开按钮候选 (企微不同版本 resource-id 会变, 用多候选)
    _PLUS_BTN_CANDIDATES: tuple[dict, ...] = (
        dict(description="更多功能"),
        dict(description="更多"),
        dict(descriptionContains="更多"),
    )

    #: 附件面板里"相册/图片"入口候选
    _GALLERY_ENTRY_CANDIDATES: tuple[dict, ...] = (
        dict(text="相册"),
        dict(text="图片"),
        dict(description="相册"),
        dict(descriptionContains="相册"),
    )

    #: 附件面板 grid 有分页 (底部 ●○), 翻页需要向左滑该 grid.
    #: 大部分入口 (文件/位置/个人名片) 在第二页.
    _PLUS_PANEL_MAX_PAGES: int = 3

    #: 相册界面右下"发送(N)"按钮候选
    _MEDIA_SEND_CANDIDATES: tuple[dict, ...] = (
        # 精确"发送"优先 (转发/文件确认弹窗右下角 Button)
        dict(text="发送", className="android.widget.Button"),
        dict(text="发送"),
        # 相册预览里的"发送(N)"
        dict(textStartsWith="发送("),
        dict(textStartsWith="发送"),
        dict(text="确定"),
        dict(textStartsWith="确定"),
        dict(descriptionContains="发送"),
    )

    def open_plus_panel(self, timeout_s: float = 3.0) -> None:
        """展开输入区右下 '+' 附件面板. 幂等: 面板已开则直接返回."""
        # 若面板里的"相册"入口已可见, 视为已展开
        for sel in self._GALLERY_ENTRY_CANDIDATES:
            if self.dev(**sel).exists:
                logger.debug("附件面板已展开")
                return

        # 需要先确保是文字模式 (语音模式没有 + 按钮)
        if not self.dev(resourceId=self.loc.input_edit).exists:
            self.enter_text_mode()

        # 1) 用户配置的 resource-id 优先 (config.locators.plus_button)
        btn = None
        if self.loc.plus_button:
            el = self.dev(resourceId=self.loc.plus_button)
            if el.exists:
                btn = el
        # 2) 兜底文本/描述候选
        if not btn:
            btn = self._first_existing(self._PLUS_BTN_CANDIDATES)
        if not btn:
            self._dump("open_plus_panel_MISS", "找不到 '+' 按钮")
            raise NavigationError(
                "找不到附件面板 '+' 按钮; UI 已 dump. "
                "请把按钮 resource-id 填到 config.locators.plus_button"
            )
        btn.click()
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            for sel in self._GALLERY_ENTRY_CANDIDATES:
                if self.dev(**sel).exists:
                    return
            time.sleep(0.2)
        self._dump("open_plus_panel_no_entry", "点了 '+' 但未见相册入口")
        raise NavigationError("展开 + 后未见相册入口")

    def open_gallery(self, timeout_s: float = 4.0) -> None:
        """在附件面板里点'相册/图片', 进入相册选择界面. 自动翻页."""
        entry = self._find_in_plus_panel(self._GALLERY_ENTRY_CANDIDATES)
        if not entry:
            self._dump("open_gallery_MISS", "附件面板里找不到相册入口")
            raise NavigationError("找不到相册入口 (已翻遍附件面板)")
        entry.click()
        # 相册界面通常有可滚动的 GridView / RecyclerView + 缩略图
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self._gallery_grid_visible():
                return
            time.sleep(0.25)
        self._dump("open_gallery_no_grid", "相册 grid 未出现")
        raise NavigationError("相册界面 grid 未出现")

    def _gallery_grid_visible(self) -> bool:
        """启发式判定相册 grid 已加载"""
        for cls in (
            "androidx.recyclerview.widget.RecyclerView",
            "android.widget.GridView",
        ):
            if self.dev(className=cls).exists:
                return True
        return False

    def pick_latest_in_gallery(
        self,
        *,
        prefer_name_substring: str | None = None,
    ) -> None:
        """
        在相册界面选中 "最新一张" (通常是左上角).
        prefer_name_substring: 若给了, 优先按文件名/描述匹配 (更稳).

        选中后企微通常会:
          - 直接进入预览+确认页 (点击缩略图), 或
          - 打勾并在右下角出现 '发送(1)' 按钮
        本方法只负责"点中缩略图", 让上层再决定按哪个发送按钮.
        """
        # 优先按文件名匹配
        if prefer_name_substring:
            el = self.dev(descriptionContains=prefer_name_substring)
            if not el.exists:
                el = self.dev(textContains=prefer_name_substring)
            if el.exists:
                el.click()
                time.sleep(0.6)
                logger.debug(f"相册: 按 name 匹配点中 {prefer_name_substring!r}")
                return

        # 兜底: 找 grid 内第一个可点击的缩略图 (通常最新一张在左上)
        thumb = self._first_gallery_thumb()
        if not thumb:
            self._dump("gallery_no_thumb", "相册里找不到缩略图")
            raise NavigationError("相册中未找到可点击缩略图")
        thumb.click()
        time.sleep(0.6)
        logger.debug("相册: 点中左上角最新一张")

    def _first_gallery_thumb(self):
        """
        从 UI dump 里找到相册 grid 内第一个 clickable 的 ImageView.
        用 XML 解析比 selector chain 稳定.
        """
        try:
            xml_str = self.dev.dump_hierarchy()
        except Exception:
            return None
        root = ET.fromstring(xml_str)

        best = None
        best_y = 10**9
        for node in root.iter("node"):
            cls = node.attrib.get("class", "")
            if "ImageView" not in cls and "ViewGroup" not in cls:
                continue
            if node.attrib.get("clickable", "false") != "true":
                continue
            bounds = node.attrib.get("bounds", "")
            m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
            if not m:
                continue
            l, t, r, b = map(int, m.groups())
            w, h = r - l, b - t
            if w < 80 or h < 80:      # 太小的忽略 (工具栏图标)
                continue
            if w > h * 3 or h > w * 3:  # 长条不是缩略图
                continue
            # 挑最上一行最左的
            if t < best_y:
                best_y = t
                best = (l, t, r, b)
        if not best:
            return None
        l, t, r, b = best
        cx, cy = (l + r) // 2, (t + b) // 2
        # 返回一个可以 .click() 的对象; uiautomator2 的 click(x,y) 直接可用,
        # 这里包装成 duck-typed
        class _Tap:
            def __init__(self, dev, x, y):
                self._dev = dev
                self.x, self.y = x, y
            def click(self):
                self._dev.click(self.x, self.y)
        return _Tap(self.dev, cx, cy)

    # ---------------- 文件浏览器 (Stage 4.5.4) ---------------- #

    #: 附件面板里"文件"入口候选 (注意: 不是"文档"! 企微里"文档"是在线文档,
    #: "文件"才是本地文件浏览器, 二者是完全不同的入口, 且"文件"在第二页)
    _FILE_ENTRY_CANDIDATES: tuple[dict, ...] = (
        dict(text="文件"),
        dict(description="文件"),
    )

    #: 点"文件"后弹出的来源选择 (不走微盘)
    _FILE_SOURCE_LOCAL_CANDIDATES: tuple[dict, ...] = (
        dict(text="从本地文件选择"),
        dict(textContains="本地文件"),
    )

    #: 文件浏览器里"手机存储/本地文件"tab 候选
    _FILE_TAB_LOCAL_CANDIDATES: tuple[dict, ...] = (
        dict(text="手机存储"),
        dict(text="本地"),
        dict(text="本地文件"),
        dict(textContains="手机"),
    )

    #: 常见目录名别名 (用于极少数需要逐级进目录的场景; SAF"最近"视图下用不到)
    _FOLDER_NAME_ALIASES: dict[str, tuple[str, ...]] = {
        "Pictures": ("Pictures",),
        "Download": ("Download", "下载"),
        "Documents": ("Documents",),
    }

    def open_file_picker(self, timeout_s: float = 3.0) -> None:
        """
        在附件面板里点"文件", 等待底部来源选择弹窗出现.
        "文件"入口通常在第二页, 会自动翻页查找.
        假定 open_plus_panel() 已调用.

        注意: 点"文件"后不会直接进入文件列表, 会先出现
        「从微盘选择 / 从本地文件选择」——需再调 choose_local_file_source().
        """
        entry = self._find_in_plus_panel(self._FILE_ENTRY_CANDIDATES)
        if not entry:
            self._dump("open_file_picker_MISS", "找不到 '文件' 入口")
            raise NavigationError("找不到 '文件' 入口 (已翻遍附件面板)")
        entry.click()
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self._first_existing(self._FILE_SOURCE_LOCAL_CANDIDATES):
                logger.debug("文件来源选择弹窗已出现")
                return
            time.sleep(0.25)
        self._dump("open_file_picker_no_sheet", "点文件后未出现来源选择弹窗")
        raise NavigationError("点'文件'后未出现来源选择弹窗")

    def choose_local_file_source(self, timeout_s: float = 5.0) -> None:
        """
        在来源弹窗里点「从本地文件选择」(不走微盘).
        全部用 text 定位, 不依赖固定坐标.
        """
        el = self._first_existing(self._FILE_SOURCE_LOCAL_CANDIDATES)
        if not el:
            self._dump("choose_local_source_MISS", "找不到'从本地文件选择'")
            raise NavigationError("找不到'从本地文件选择'按钮")
        el.click()
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            for sel in self._FILE_TAB_LOCAL_CANDIDATES:
                if self.dev(**sel).exists:
                    return
            if self._gallery_grid_visible():
                return
            time.sleep(0.25)
        self._dump("choose_local_source_no_browser", "本地文件浏览器未加载")
        raise NavigationError("本地文件浏览器加载超时")

    def switch_to_local_storage(self) -> None:
        """如果文件浏览器有 tab 栏, 切到"手机存储" (幂等)"""
        for sel in self._FILE_TAB_LOCAL_CANDIDATES:
            el = self.dev(**sel)
            if el.exists:
                el.click()
                time.sleep(0.8)
                return
        logger.debug("未见'手机存储'tab, 假定已在本地目录")

    def navigate_to_remote_file(self, remote: str) -> None:
        """
        选中 adb push 上去的文件.

        策略 (SAF 优先):
          1) 先在当前视图直接按文件名匹配 (SAF "最近的文件" 里 push 完立刻出现)
          2) 找不到, 才走目录导航兜底: /sdcard/Pictures/wecom_batch/ → 逐级点入
        """
        parts = [p for p in remote.strip("/").split("/") if p]
        if not parts:
            raise NavigationError(f"非法 remote 路径: {remote!r}")
        filename = parts[-1]

        # 1) SAF "最近" 视图: 文件名前缀 wb_xxxxxx_ 独特, 直接匹配
        if self.dev(textContains=filename).exists:
            logger.debug(f"文件: 直接在当前视图命中 {filename!r}")
            self.pick_file_by_name(filename)
            return

        # 2) 兜底: 走传统目录导航 (企微自带浏览器 / 老 Android 版本)
        dirs = parts[:-1]
        if dirs and dirs[0].lower() in ("sdcard", "storage", "emulated"):
            dirs = dirs[1:]
        if dirs and dirs[0] == "0":
            dirs = dirs[1:]

        self.switch_to_local_storage()
        for folder in dirs:
            self._enter_folder(folder)
        self.pick_file_by_name(filename)

    def _enter_folder(self, folder: str, *, scroll_max: int = 6) -> None:
        """在当前列表里点进一个文件夹 (支持常见别名)"""
        names = self._FOLDER_NAME_ALIASES.get(folder, (folder,))
        for attempt in range(scroll_max + 1):
            for name in names:
                for sel in (dict(text=name), dict(textContains=name)):
                    el = self.dev(**sel)
                    if el.exists:
                        el.click()
                        time.sleep(0.8)
                        logger.debug(f"文件: 进入目录 {name!r}")
                        return
            if attempt < scroll_max:
                self._scroll_file_list_down()
        self._dump("enter_folder_MISS", f"找不到目录 {folder!r}")
        raise NavigationError(f"文件列表里找不到目录 {folder!r}")

    def _scroll_file_list_down(self) -> None:
        """在文件列表区域向下滚一页 (用当前屏幕尺寸, 自适应窗口大小)"""
        info = self.dev.info
        w, h = info["displayWidth"], info["displayHeight"]
        self.dev.swipe(w // 2, int(h * 0.72), w // 2, int(h * 0.28),
                       duration=0.25)
        time.sleep(0.4)

    def pick_file_by_name(self, name_substring: str,
                         *, scroll_max: int = 8) -> None:
        """
        在当前文件列表里找到含 name_substring 的条目并点击.
        必要时滚动列表 (最多 scroll_max 次).
        """
        for i in range(scroll_max + 1):
            el = self.dev(textContains=name_substring)
            if el.exists:
                el.click()
                time.sleep(0.8)
                logger.debug(f"文件: 已选 {name_substring!r}")
                return
            if i == scroll_max:
                break
            self._scroll_file_list_down()
        self._dump("pick_file_MISS", f"找不到文件 {name_substring!r}")
        raise NavigationError(f"文件列表里找不到 {name_substring!r}")

    def tap_media_send(
        self, *, wait_after_s: float = 1.5, appear_timeout_s: float = 5.0
    ) -> None:
        """
        点右下"发送"按钮.

        场景覆盖:
          - 相册预览/多选: "发送(N)"
          - 文件/名片转发确认弹窗: "发送给：xx ...  [取消] [发送]"
          - 通用确认: "确定"

        企微里 text="发送" 的 TextView 本身可能 clickable=false, 事件由祖先
        ViewGroup 消费. uiautomator2 的 .click() 会 tap 到 bounds 中心,
        Android 事件冒泡会交给可点击祖先, 所以不需要显式检查 clickable.
        """
        deadline = time.perf_counter() + appear_timeout_s
        last_dump_hint = "无按钮候选命中"
        while time.perf_counter() < deadline:
            for sel in self._MEDIA_SEND_CANDIDATES:
                el = self.dev(**sel)
                if el.exists:
                    el.click()
                    time.sleep(wait_after_s)
                    logger.debug(f"tap_media_send: 命中 {sel}")
                    return
            time.sleep(0.25)
        self._dump("tap_media_send_MISS", last_dump_hint)
        raise NavigationError("找不到 '发送' 按钮; UI 已 dump")

    # ---------------- 工具 ---------------- #

    def _first_existing(self, candidates: tuple[dict, ...]):
        for sel in candidates:
            el = self.dev(**sel)
            if el.exists:
                return el
        return None

    def _find_in_plus_panel(
        self,
        candidates: tuple[dict, ...],
        *,
        max_pages: int | None = None,
    ):
        """
        在附件面板 grid 里找入口, 找不到就向左翻页 (最多 max_pages 次).
        返回命中的 UiObject 或 None.

        企微附件面板结构:
            RelativeLayout id/ij2      (整个面板容器, scrollable=false)
              └ GridView   id/ak3      (grid 本体, scrollable=false)
                  └ 8 个 slot / 页
        虽然容器 scrollable=false, 但手指滑动时 Android 内部会做位移动画切页.
        必须用**控件级** UiObject.swipe("left") 才能触发正确的手势 (全局 swipe
        经常被 GridView item 消费当成 tap).
        """
        if max_pages is None:
            max_pages = self._PLUS_PANEL_MAX_PAGES

        for page in range(max_pages):
            el = self._first_existing(candidates)
            if el:
                if page > 0:
                    logger.debug(f"附件面板: 在第 {page + 1} 页命中")
                return el
            if page < max_pages - 1:
                if not self._swipe_plus_panel_left():
                    logger.debug("附件面板: 找不到 grid, 无法翻页")
                    break
                time.sleep(0.7)
        return None

    def _swipe_plus_panel_left(self) -> bool:
        """
        在附件面板 grid 上向左滑一页. 距离要接近满宽, 否则被判定为无效手势.

        三重策略, 逐个尝试:
          1) adb shell input swipe (系统级 InputDispatcher, 最稳)
          2) dev.drag  (uiautomator2 慢速拖拽)
          3) UiObject.swipe("left")  (控件级, 但可能距离不够)
        """
        grid = self.dev(className="android.widget.GridView")
        if not grid.exists:
            grid = self.dev(resourceId="com.tencent.wework:id/ak3")
        if not grid.exists:
            return False

        b = grid.info["bounds"]
        l, r = b["left"], b["right"]
        cy = (b["top"] + b["bottom"]) // 2
        # 起点/终点几乎贴到 grid 左右边缘 (5% 边距)
        margin = int((r - l) * 0.05)
        sx = r - margin
        ex = l + margin

        # ---- 1) adb shell input swipe (ms 精度, 走系统级) ----
        try:
            duration_ms = 500
            self.dev.shell(f"input swipe {sx} {cy} {ex} {cy} {duration_ms}")
            logger.debug(
                f"附件面板: adb input swipe {sx},{cy} → {ex},{cy}  "
                f"({duration_ms}ms)"
            )
            return True
        except Exception as e:
            logger.debug(f"adb input swipe 失败: {e}, 回退 dev.drag")

        # ---- 2) dev.drag (uiautomator2) ----
        try:
            self.dev.drag(sx, cy, ex, cy, duration=0.6)
            logger.debug(f"附件面板: dev.drag {sx},{cy} → {ex},{cy}")
            return True
        except Exception as e:
            logger.debug(f"dev.drag 失败: {e}, 回退 UiObject.swipe")

        # ---- 3) 控件级 ----
        try:
            grid.swipe("left", steps=40)
            logger.debug("附件面板: UiObject.swipe('left')")
            return True
        except Exception as e:
            logger.debug(f"所有滑动方法都失败: {e}")
            return False

    def _dump(self, name: str, msg: str, dump_dir: Path | str = "runtime/nav_dumps") -> None:
        d = resolve_path(dump_dir)
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_p = d / f"{name}_{ts}.xml"
        png_p = d / f"{name}_{ts}.png"
        try:
            xml_p.write_text(self.dev.dump_hierarchy(), encoding="utf-8")
            self.dev.screenshot(str(png_p))
            logger.warning(f"{msg}; dump → {xml_p.name} / {png_p.name}")
        except Exception as e:
            logger.debug(f"dump 失败: {e}")

    def tap_send_button(
        self,
        *,
        wait_after_s: float = 1.0,
        dump_dir: Path | str = "runtime/nav_dumps",
    ) -> None:
        """
        点击"发送"按钮. 优先用 config.locators.send_button (resource-id),
        没配就用文本候选. 全部失败时 dump 当前 UI 便于分析后回补.
        """
        # 1) 用户显式配置 resource-id
        if self.loc.send_button:
            el = self.dev(resourceId=self.loc.send_button)
            if el.exists:
                el.click()
                logger.debug(f"发送: resourceId={self.loc.send_button}")
                time.sleep(wait_after_s)
                return
            logger.debug(
                f"配置的 send_button={self.loc.send_button} 不存在, 尝试文本候选"
            )

        # 2) 文本候选 (TextView 本身可能不 clickable, 靠父级冒泡消费点击)
        for sel in self._SEND_TEXT_CANDIDATES:
            el = self.dev(**sel)
            if el.exists:
                el.click()
                logger.debug(f"发送: {sel}")
                time.sleep(wait_after_s)
                return

        # 3) 全部失败 → dump 便于修 locator
        d = resolve_path(dump_dir)
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_path = d / f"send_button_MISS_{ts}.xml"
        png_path = d / f"send_button_MISS_{ts}.png"
        try:
            xml_path.write_text(self.dev.dump_hierarchy(), encoding="utf-8")
            self.dev.screenshot(str(png_path))
        except Exception as e:
            logger.debug(f"dump 失败: {e}")
        raise NavigationError(
            f"未找到可点击的'发送'按钮; UI 已 dump → {xml_path.name}. "
            f"请分析后把 resource-id 填到 config.locators.send_button"
        )

    # ================================================================ #
    #          Stage 4.5.5.2  FTA 转发导航 (单选)                       #
    # ================================================================ #

    #: 文件传输助手聊天名称
    FTA_NAME: str = "文件传输助手"

    #: 聊天列表容器候选 (企微不同版本可能不同)
    _CHAT_LIST_CANDIDATES: tuple[dict, ...] = (
        dict(className="androidx.recyclerview.widget.RecyclerView"),
        dict(className="android.support.v7.widget.RecyclerView"),
        dict(className="android.widget.ListView"),
    )

    #: "转发" 上下文菜单项候选
    _FORWARD_MENU_CANDIDATES: tuple[dict, ...] = (
        dict(text="转发"),
        dict(textContains="转发"),
        dict(description="转发"),
    )

    #: 选人界面搜索图标候选
    _CONTACT_SEARCH_ICON_CANDIDATES: tuple[dict, ...] = (
        dict(resourceId="com.tencent.wework:id/nt8"),
        dict(description="搜索"),
        dict(descriptionContains="搜索"),
    )

    #: 选人界面搜索输入框候选
    _CONTACT_SEARCH_EDIT_CANDIDATES: tuple[dict, ...] = (
        dict(className="android.widget.EditText"),
    )

    #: 二次确认弹窗 "发送" 按钮候选
    #: 注意: 弹窗标题含 "分别发送给:" 所以不能用 textContains="发送"
    _FORWARD_SEND_CONFIRM_CANDIDATES: tuple[dict, ...] = (
        dict(textStartsWith="发送"),
        dict(text="确定"),
        dict(text="确认"),
        dict(textStartsWith="确定发送"),
    )

    # ---- FTA 入口 ---- #

    def open_fta(self) -> None:
        """
        打开"文件传输助手"聊天窗口。
        先回消息列表, 再调 open_chat. 若失败抛 NavigationError.
        """
        logger.info("open_fta: 打开文件传输助手")
        self.goto_home()
        self.open_chat(self.FTA_NAME)

    # ---- 气泡枚举 ---- #

    @staticmethod
    def _collect_text(node: ET.Element) -> str:
        """
        递归拼接节点自身及所有子节点的 text 属性。
        spike4 只抓 long-clickable 节点自身 text, 导致很多气泡 text 为空;
        4.5.5.2 增强: 遍历子树拼接, 使 fta_locator 文本匹配更可靠。
        """
        parts: list[str] = []
        for n in node.iter("node"):
            t = n.attrib.get("text", "").strip()
            if t:
                parts.append(t)
        return " ".join(parts)

    def enumerate_fta_bubbles(self) -> list[BubbleInfo]:
        """
        枚举当前聊天窗口中可见的"消息气泡"节点 (long-clickable).

        返回从上到下排列的 BubbleInfo 列表 (index 0 = 最上方/最旧,
        index -1 = 最下方/最新)。

        依赖 UI dump 解析, 比 selector 遍历更稳。
        """
        logger.debug("enumerate_fta_bubbles: 开始枚举")

        try:
            xml_str = self.dev.dump_hierarchy()
        except Exception as e:
            raise NavigationError(f"dump_hierarchy 失败: {e}")

        root = ET.fromstring(xml_str)
        bubbles: list[BubbleInfo] = []

        for node in root.iter("node"):
            cls = node.attrib.get("class", "")
            if "RecyclerView" not in cls and "ListView" not in cls:
                continue
            # 找容器下所有 long-clickable 节点
            for child in node.iter("node"):
                if child.attrib.get("long-clickable", "false") != "true":
                    continue
                bounds_str = child.attrib.get("bounds", "")
                m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
                if not m:
                    continue
                left, top, right, bottom = map(int, m.groups())
                w, h = right - left, bottom - top
                if w < 40 or h < 40:
                    continue

                full_text = self._collect_text(child)
                bubbles.append(BubbleInfo(
                    cx=(left + right) // 2,
                    cy=(top + bottom) // 2,
                    bounds=(left, top, right, bottom),
                    text=full_text,
                    content_desc=child.attrib.get("content-desc", ""),
                    resource_id=child.attrib.get("resource-id", ""),
                    cls=cls,
                ))
            break  # 只看第一个匹配的容器

        bubbles.sort(key=lambda b: b.cy)
        logger.debug(f"enumerate_fta_bubbles: 发现 {len(bubbles)} 个气泡")
        for i, b in enumerate(bubbles):
            logger.debug(
                f"  #{i}  y={b.cy:>4}  text={b.text[:40]!r}"
            )
        return bubbles

    # ---- 气泡定位 ---- #

    def find_bubble_by_locator(
        self,
        text_substring: str,
        *,
        scroll_up_max: int = 3,
    ) -> BubbleInfo:
        """
        按 AssetEntry.fta_locator 子串在 FTA 气泡中定位。
        先在当前可见区域查找, 找不到则向上滚动 (最多 scroll_up_max 次)
        以加载更旧的消息。

        返回匹配的 BubbleInfo; 未找到抛 NavigationError.
        """
        logger.info(f"find_bubble_by_locator: {text_substring!r}")
        for attempt in range(scroll_up_max + 1):
            bubbles = self.enumerate_fta_bubbles()
            for b in bubbles:
                if text_substring in b.text or text_substring in b.content_desc:
                    logger.debug(
                        f"find_bubble_by_locator: 命中 @({b.cx},{b.cy}) "
                        f"text={b.text[:40]!r}"
                    )
                    return b
            if attempt < scroll_up_max:
                logger.debug(
                    f"find_bubble_by_locator: 当前页未见, 向上滚动 "
                    f"({attempt + 1}/{scroll_up_max})"
                )
                self._scroll_chat_up()

        self._dump("find_bubble_MISS", f"未找到含 {text_substring!r} 的气泡")
        raise NavigationError(
            f"FTA 中未找到含 {text_substring!r} 的气泡; "
            f"已滚动 {scroll_up_max} 次, UI 已 dump"
        )

    def _scroll_chat_up(self) -> None:
        """在聊天窗口向上滚动一段以加载更旧消息."""
        info = self.dev.info
        w, h = info["displayWidth"], info["displayHeight"]
        self.dev.swipe(
            w // 2, int(h * 0.30),
            w // 2, int(h * 0.72),
            duration=0.3,
        )
        time.sleep(0.8)

    # ---- 长按 & 转发菜单 ---- #

    def long_press_bubble(self, cx: int, cy: int,
                          duration: float = 0.8) -> None:
        """
        长按指定坐标弹出上下文菜单.
        duration 秒数, 默认 0.8s (足够触发企微长按菜单).
        """
        logger.debug(f"long_press_bubble: @({cx},{cy}) duration={duration}s")
        self.dev.long_click(cx, cy, duration=duration)
        time.sleep(1.0)

    def tap_forward_menu(self, timeout_s: float = 3.0) -> None:
        """
        在长按弹出的上下文菜单里点击"转发".
        若超时未找到, dump UI 并抛 NavigationError.
        """
        logger.debug("tap_forward_menu: 查找 '转发' 菜单项")
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            el = self._first_existing(self._FORWARD_MENU_CANDIDATES)
            if el:
                el.click()
                time.sleep(1.2)
                logger.debug("tap_forward_menu: 已点击 '转发'")
                return
            time.sleep(0.2)
        self._dump("tap_forward_MISS", "上下文菜单未找到 '转发'")
        raise NavigationError(
            "长按后未找到 '转发' 菜单项; UI 已 dump. "
            "请检查长按是否成功弹出菜单"
        )

    # ---- 选人 (单选) ---- #

    def pick_forward_target(self, contact: str,
                            timeout_s: float = 6.0) -> None:
        """
        在"选择聊天"界面选中目标联系人 (单选模式).

        策略:
          1) 先在"最近聊天"列表中直接按 text 匹配点击
          2) 若不在列表, 点搜索图标→输入→搜索结果点击

        4.5.5.2 只做单选; 多选群发留到 4.5.7.
        """
        logger.info(f"pick_forward_target: {contact!r}")

        # 策略 1: 最近列表直点
        if self._click_contact_row(contact):
            return

        # 策略 2: 搜索
        logger.debug("pick_forward_target: 最近列表未见, 尝试搜索")
        for sel in self._CONTACT_SEARCH_ICON_CANDIDATES:
            icon = self.dev(**sel)
            if not icon.exists:
                continue
            logger.debug(f"pick_forward_target: 点击搜索图标 {sel}")
            icon.click()
            time.sleep(0.8)
            edit = self._first_existing(self._CONTACT_SEARCH_EDIT_CANDIDATES)
            if not edit:
                self.dev.press("back")
                time.sleep(0.5)
                continue

            edit.click()
            time.sleep(0.3)
            try:
                self.dev.clear_text()
            except Exception:
                pass
            self.dev.send_keys(contact)
            time.sleep(1.2)

            if self._click_contact_row(contact):
                return

            logger.debug("pick_forward_target: 搜索后仍未找到")
            self._dump("pick_forward_MISS", f"搜索 {contact!r} 无结果")
            raise NavigationError(
                f"选人界面搜索 {contact!r} 后未命中; UI 已 dump"
            )

        self._dump("pick_forward_no_search", "找不到搜索图标")
        raise NavigationError(
            f"选人界面既不在最近列表也找不到搜索入口; UI 已 dump"
        )

    def _click_contact_row(self, contact: str) -> bool:
        """点击选人列表中匹配联系人名的行. 返回是否成功."""
        for sel in (dict(text=contact), dict(textContains=contact)):
            el = self.dev(**sel)
            if el.exists:
                el.click()
                time.sleep(1.0)
                logger.debug(f"_click_contact_row: 命中 {sel}")
                return True
        return False

    # ---- 确认发送 ---- #

    def confirm_forward_send(self, timeout_s: float = 3.0) -> None:
        """
        处理转发的二次确认弹窗 → 点"发送".

        企微转发流程:
          选人 → 弹窗 "分别发送给: XXX ... [取消] [发送]" → 点发送
        部分版本没有二次弹窗 (选人=直接发送), 此时也视为成功.
        """
        logger.debug("confirm_forward_send: 查找确认按钮")
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            el = self._first_existing(self._FORWARD_SEND_CONFIRM_CANDIDATES)
            if el:
                el.click()
                time.sleep(1.5)
                logger.info("confirm_forward_send: 已确认发送")
                return
            time.sleep(0.2)
        # 没有确认弹窗也算成功 (某些版本选人即发送)
        logger.debug("confirm_forward_send: 未见二次确认弹窗, 可能已直接发送")

    # ---- 组合: 完整单选转发链路 ---- #

    def forward_bubble_to(
        self,
        fta_locator: str,
        contact: str,
        *,
        scroll_up_max: int = 3,
    ) -> None:
        """
        完整单选转发链路:
          FTA 定位气泡 → 长按 → 转发 → 选人 → 确认.

        这是 4.5.5.3+ ForwardSender 的底层调用。

        Args:
            fta_locator: AssetEntry.fta_locator 子串, 用于在 FTA 气泡中定位
            contact: 目标联系人/群名
            scroll_up_max: 气泡搜索时最多向上滚动次数

        Raises:
            NavigationError: 任何步骤失败
        """
        logger.info(
            f"forward_bubble_to: locator={fta_locator!r} → {contact!r}"
        )

        # 1) 定位气泡
        bubble = self.find_bubble_by_locator(
            fta_locator, scroll_up_max=scroll_up_max
        )

        # 2) 长按
        self.long_press_bubble(bubble.cx, bubble.cy)

        # 3) 点转发
        self.tap_forward_menu()

        # 4) 选人
        self.pick_forward_target(contact)

        # 5) 确认
        self.confirm_forward_send()

        logger.info(
            f"forward_bubble_to: 完成 {fta_locator!r} → {contact!r}"
        )

    # ================================================================ #
    #          Stage 4.5.5.4  FTA 素材保鲜                              #
    # ================================================================ #

    def forward_to_self(
        self,
        fta_locator: str,
        *,
        scroll_up_max: int = 5,
    ) -> None:
        """
        保鲜: 把 FTA 中匹配 fta_locator 的老气泡转发给"文件传输助手"本人,
        使其在 FTA 里变成最新一条 (bottom).

        用途:
          * 转发类素材 (小程序/位置/视频号) 靠 fta_locator 在 FTA 气泡里定位;
            若素材老旧、被后续消息淹没, find_bubble_by_locator 需向上滚很多屏.
          * 定期 forward_to_self 可把关键素材"顶"回最新, 提高定位效率.

        实现: 复用 forward_bubble_to(locator, "文件传输助手").
              因为转发目标是当前所在的 FTA 本身, 转发完成后就自动出现在气泡列表底部.

        与 4.5.5.3 ForwardSender 的区别:
          - ForwardSender: 转给客户
          - forward_to_self: 转给 FTA 自己 (保鲜, 不给客户看)

        Args:
            fta_locator: 要保鲜的气泡内容子串
            scroll_up_max: 定位时最多向上滚动次数 (老素材可能被淹没较深)

        Raises:
            NavigationError: 定位/转发失败
        """
        logger.info(f"forward_to_self: 保鲜 {fta_locator!r}")
        # 假定当前已经在 FTA. 调用方 (如 BatchRunner) 需自行 open_fta.
        # 这里不主动 open_fta 是为了让保鲜循环高效: 上层可一次 open_fta 后连续保鲜多个 tag.
        self.forward_bubble_to(
            fta_locator,
            self.FTA_NAME,
            scroll_up_max=scroll_up_max,
        )
        logger.info(f"forward_to_self: 完成 {fta_locator!r}")

    # ================================================================ #
    #                     Stage 4.5.6  个人名片                          #
    # ================================================================ #

    #: 附件面板里 "个人名片" 入口候选 (企微 real-world dump: text=个人名片,
    #: resource-id=com.tencent.wework:id/ajz, clickable=false — 靠父格 grid cell
    #: 冒泡消费 tap. 注意与 "企业名片" 区分, 不是同一个入口.)
    _CONTACT_CARD_ENTRY_CANDIDATES: tuple[dict, ...] = (
        dict(text="个人名片"),
        dict(description="个人名片"),
        dict(descriptionContains="个人名片"),
    )

    #: 好友选择器里搜索图标候选 (与 FTA 选人共用一批 resourceId, 但保留单独常量便于调整)
    _CARD_PICKER_SEARCH_ICON_CANDIDATES: tuple[dict, ...] = (
        dict(resourceId="com.tencent.wework:id/nt8"),
        dict(description="搜索"),
        dict(descriptionContains="搜索"),
    )

    #: 名片二次确认弹窗 "发送" 按钮候选
    #: 与 forward 类似, 弹窗标题可能含 "发送给:", 用 textStartsWith 避免误点标题
    _CARD_SEND_CONFIRM_CANDIDATES: tuple[dict, ...] = (
        dict(text="发送", className="android.widget.Button"),
        dict(textStartsWith="发送"),
        dict(text="确定"),
        dict(text="确认"),
    )

    def open_contact_card_picker(self, timeout_s: float = 4.0) -> None:
        """
        在附件面板里找"个人名片"并点击, 进入好友选择器.

        假定输入区已进入文字模式 (open_plus_panel 会自动切).
        个人名片入口通常在附件面板第二页, 复用 _find_in_plus_panel 自动翻页.

        Raises:
            NavigationError: 附件面板打不开 / 找不到"个人名片"入口 / 选择器未加载
        """
        logger.debug("open_contact_card_picker: 准备打开个人名片选择器")
        # 1) 展开 + 面板 (幂等)
        self.open_plus_panel()

        # 2) 找 "个人名片" 入口 (可能在第 2/3 页, _find_in_plus_panel 会翻页)
        entry = self._find_in_plus_panel(self._CONTACT_CARD_ENTRY_CANDIDATES)
        if not entry:
            self._dump(
                "open_contact_card_picker_MISS",
                "附件面板里找不到 '个人名片' 入口",
            )
            raise NavigationError(
                "找不到 '个人名片' 入口 (已翻遍附件面板); "
                "注意与 '企业名片' 区分"
            )
        entry.click()

        # 3) 等待选择器加载 (启发式: 出现 EditText 搜索栏 或 联系人 ListView)
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self.dev(className="android.widget.EditText").exists:
                logger.debug("open_contact_card_picker: 选择器已加载 (搜索栏可见)")
                return
            # 兜底: 有些版本直接列表
            if self.dev(className="android.widget.ListView").exists:
                logger.debug("open_contact_card_picker: 选择器已加载 (ListView)")
                return
            if self.dev(
                className="androidx.recyclerview.widget.RecyclerView"
            ).exists:
                logger.debug("open_contact_card_picker: 选择器已加载 (RecyclerView)")
                return
            time.sleep(0.2)

        self._dump(
            "open_contact_card_picker_no_ui",
            "点击 '个人名片' 后好友选择器未加载",
        )
        raise NavigationError("好友选择器加载超时")

    def pick_friend_for_card(
        self,
        friend_name: str,
        timeout_s: float = 6.0,
    ) -> None:
        """
        在名片选择器里选中目标好友.

        策略 (与 pick_forward_target 同族, 但语义独立):
          1) 若可见列表里已经能匹配到 friend_name, 直接点
          2) 否则点搜索图标 → 输入 → 点搜索结果

        Raises:
            NavigationError: 找不到目标好友
        """
        logger.info(f"pick_friend_for_card: {friend_name!r}")

        # 策略 1: 直点
        if self._click_contact_row(friend_name):
            return

        # 策略 2: 搜索
        logger.debug("pick_friend_for_card: 列表未见, 尝试搜索")
        for sel in self._CARD_PICKER_SEARCH_ICON_CANDIDATES:
            icon = self.dev(**sel)
            if not icon.exists:
                continue
            logger.debug(f"pick_friend_for_card: 点击搜索图标 {sel}")
            icon.click()
            time.sleep(0.6)
            edit = self.dev(className="android.widget.EditText")
            if not edit.exists:
                self.dev.press("back")
                time.sleep(0.4)
                continue

            edit.click()
            time.sleep(0.25)
            try:
                self.dev.clear_text()
            except Exception:
                pass
            self.dev.send_keys(friend_name)
            time.sleep(1.0)

            if self._click_contact_row(friend_name):
                return

            self._dump(
                "pick_friend_for_card_MISS",
                f"搜索 {friend_name!r} 后仍未命中",
            )
            raise NavigationError(
                f"名片选择器搜索 {friend_name!r} 未命中; UI 已 dump"
            )

        # EditText 已可见 → 直接搜, 不需要点图标
        edit = self.dev(className="android.widget.EditText")
        if edit.exists:
            edit.click()
            time.sleep(0.25)
            try:
                self.dev.clear_text()
            except Exception:
                pass
            self.dev.send_keys(friend_name)
            time.sleep(1.0)
            if self._click_contact_row(friend_name):
                return

        self._dump(
            "pick_friend_for_card_no_search",
            "找不到搜索图标, 也没有可用 EditText",
        )
        raise NavigationError(
            f"名片选择器既不在可见列表, 也找不到搜索入口 (friend={friend_name!r})"
        )

    def confirm_card_send(self, timeout_s: float = 3.0) -> None:
        """
        名片二次确认弹窗点"发送". 若无弹窗视为已直接发送.

        与 confirm_forward_send 类似, 但候选顺序更强调 Button 类型
        (个人名片确认弹窗按钮多为 android.widget.Button).
        """
        logger.debug("confirm_card_send: 查找确认按钮")
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            el = self._first_existing(self._CARD_SEND_CONFIRM_CANDIDATES)
            if el:
                el.click()
                time.sleep(1.2)
                logger.info("confirm_card_send: 已确认发送")
                return
            time.sleep(0.2)
        logger.debug("confirm_card_send: 未见二次确认弹窗, 可能已直接发送")

    # ================================================================ #
    #                Stage 4.5.7  FTA 多选群发                          #
    # ================================================================ #

    #: 选人界面右上"多选✓"图标候选 (spike4 real dump: nt3 = 最右图标)
    _MULTISELECT_ICON_CANDIDATES: tuple[dict, ...] = (
        dict(resourceId="com.tencent.wework:id/nt3"),
        dict(description="多选"),
        dict(descriptionContains="多选"),
    )

    #: 多选完成后底部 "完成/发送(N)/确定(N)" 按钮候选
    _MULTISELECT_DONE_CANDIDATES: tuple[dict, ...] = (
        dict(resourceId="com.tencent.wework:id/lt5"),
        dict(textStartsWith="发送"),
        dict(textStartsWith="完成"),
        dict(textStartsWith="确定"),
    )

    def enter_multi_select_mode(self, timeout_s: float = 3.0) -> None:
        """
        在"选择聊天"界面点右上多选✓图标, 进入勾选模式.

        幂等: 若底部"完成/发送(N)"按钮已可见, 视为已进入多选模式.
        """
        # 幂等检查: 底部按钮已在 → 已是多选
        if self._first_existing(self._MULTISELECT_DONE_CANDIDATES):
            logger.debug("enter_multi_select_mode: 已在多选模式")
            return

        icon = self._first_existing(self._MULTISELECT_ICON_CANDIDATES)
        if not icon:
            self._dump("enter_multi_select_MISS", "找不到多选图标")
            raise NavigationError(
                "选人界面找不到多选图标; UI 已 dump. "
                "请检查是否在'选择聊天'界面, 或 resource-id 已变化"
            )
        icon.click()
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            # 进入多选模式的标志: 底部出现完成/发送按钮, 或列表项前面出现 checkbox
            if self._first_existing(self._MULTISELECT_DONE_CANDIDATES):
                logger.debug("enter_multi_select_mode: 已进入多选模式")
                return
            if self.dev(className="android.widget.CheckBox").exists:
                logger.debug("enter_multi_select_mode: checkbox 已出现")
                return
            time.sleep(0.2)
        # 未见明显标志, 但也不硬失败 (某些版本可能没有底部按钮直到勾选后才出现)
        logger.debug(
            "enter_multi_select_mode: 未观察到明显标志, 继续 (依赖后续勾选验证)"
        )

    def tick_contact_in_multi_select(
        self,
        name: str,
        *,
        search_if_missing: bool = True,
    ) -> bool:
        """
        在多选模式下勾选一个联系人. 返回是否勾选成功.

        策略:
          1) 在当前可见列表按 text 匹配点击
          2) 若不可见且 search_if_missing=True, 走搜索路径 (输入 → 结果点击)
             搜索路径参考 spike4 _multiselect_search_and_tick.

        不抛异常; 未命中返回 False, 让上层决定是否 fallback 到单选.
        """
        # 策略 1: 直接列表命中
        for sel in (dict(text=name), dict(textContains=name)):
            el = self.dev(**sel)
            if el.exists:
                el.click()
                time.sleep(0.4)
                logger.debug(f"tick_contact_in_multi_select: 直接勾选 {name!r}")
                return True

        if not search_if_missing:
            return False

        # 策略 2: 搜索
        # 找搜索图标 (nt8) 或已存在的 EditText
        edit = self.dev(className="android.widget.EditText")
        if not edit.exists:
            for sel in (
                dict(resourceId="com.tencent.wework:id/nt8"),
                dict(description="搜索"),
            ):
                icon = self.dev(**sel)
                if icon.exists:
                    icon.click()
                    time.sleep(0.5)
                    break
            edit = self.dev(className="android.widget.EditText")
        if not edit.exists:
            logger.debug(
                f"tick_contact_in_multi_select: 无搜索入口, {name!r} 未勾选"
            )
            return False

        edit.click()
        time.sleep(0.25)
        try:
            self.dev.clear_text()
        except Exception:
            pass
        self.dev.send_keys(name)
        time.sleep(0.9)

        for sel in (dict(text=name), dict(textContains=name)):
            el = self.dev(**sel)
            if el.exists:
                el.click()
                time.sleep(0.4)
                logger.debug(
                    f"tick_contact_in_multi_select: 搜索勾选 {name!r}"
                )
                # 尝试关掉搜索栏 (清空 + back), 回到勾选列表. 失败也无妨.
                try:
                    self.dev.clear_text()
                except Exception:
                    pass
                return True
        logger.debug(
            f"tick_contact_in_multi_select: 搜索 {name!r} 无结果"
        )
        return False

    def tap_multi_select_done(self, timeout_s: float = 3.0) -> None:
        """
        点击多选底部 "完成/发送(N)/确定(N)" 按钮.
        找不到按钮 → dump + NavigationError.
        """
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            el = self._first_existing(self._MULTISELECT_DONE_CANDIDATES)
            if el:
                el.click()
                time.sleep(1.0)
                logger.debug("tap_multi_select_done: 已点完成/发送")
                return
            time.sleep(0.2)
        self._dump("multi_select_done_MISS", "找不到完成/发送按钮")
        raise NavigationError("多选底部 '完成/发送' 按钮未出现; UI 已 dump")

    def forward_bubble_multi(
        self,
        fta_locator: str,
        contacts: list[str],
        *,
        scroll_up_max: int = 3,
    ) -> list[str]:
        """
        多选群发转发链路:
          FTA 定位气泡 → 长按 → 转发 → 进多选 → 逐个勾选 → 完成 → 确认

        Returns:
            未勾中的 contacts 列表. 上层 (ForwardSender) 应对这些回退到
            单选 forward_bubble_to.

        Raises:
            NavigationError: 定位/长按/转发/多选入口等"硬失败".
                             联系人勾不上 (软失败) 不抛异常, 只放进返回值.

        备注:
            * 若所有联系人都勾不上, 会 press("back") 试着退出多选界面, 且把
              全部 contacts 作为 missed 返回.
            * 若 len(contacts)==1, 也可以走这个方法 (但通常上层应直接用
              forward_bubble_to 单选路径).
        """
        if not contacts:
            raise ValueError("forward_bubble_multi: contacts 不能为空")

        logger.info(
            f"forward_bubble_multi: locator={fta_locator!r} → "
            f"{len(contacts)} 人: {contacts}"
        )

        # 1) 定位 → 长按 → 转发
        bubble = self.find_bubble_by_locator(
            fta_locator, scroll_up_max=scroll_up_max
        )
        self.long_press_bubble(bubble.cx, bubble.cy)
        self.tap_forward_menu()

        # 2) 进多选
        self.enter_multi_select_mode()

        # 3) 逐个勾选
        missed: list[str] = []
        ticked: list[str] = []
        for c in contacts:
            if self.tick_contact_in_multi_select(c):
                ticked.append(c)
            else:
                missed.append(c)

        logger.info(
            f"forward_bubble_multi: 已勾 {len(ticked)}/{len(contacts)} "
            f"(missed={missed})"
        )

        # 4) 全部勾不上 → 退回, 交给上层单选兜底
        if not ticked:
            logger.warning(
                "forward_bubble_multi: 无任何联系人勾中, 退回多选界面"
            )
            try:
                self.dev.press("back")
                time.sleep(0.5)
                self.dev.press("back")
                time.sleep(0.5)
            except Exception as e:
                logger.debug(f"退出多选界面失败, 忽略: {e}")
            return list(contacts)

        # 5) 完成 → 确认
        self.tap_multi_select_done()
        self.confirm_forward_send()

        logger.info(
            f"forward_bubble_multi: 完成 (ticked={ticked}, missed={missed})"
        )
        return missed

    def send_contact_card(
        self,
        friend_name: str,
        *,
        after_send_s: float = 1.0,
    ) -> None:
        """
        完整"发送个人名片"链路 (供 ContactCardSender 调用):

          1) open_contact_card_picker()   # + → 个人名片
          2) pick_friend_for_card(name)   # 选目标好友
          3) confirm_card_send()          # 确认发送

        假定 open_chat 已完成, 当前在目标客户的聊天窗口.

        Args:
            friend_name: 要作为名片分享出去的好友名
            after_send_s: 发送后等 UI 稳定的秒数
        """
        logger.info(f"send_contact_card: 分享 {friend_name!r} 的名片")
        self.open_contact_card_picker()
        self.pick_friend_for_card(friend_name)
        self.confirm_card_send()
        time.sleep(after_send_s)
        logger.info(f"send_contact_card: 完成 {friend_name!r}")

    # ================================================================ #
    #                Stage 4.5.8  收藏表情 (Sticker)                    #
    # ================================================================ #

    #: 输入区 emoji 表情按钮候选 (企微 real dump 中 emoji 按钮无稳定 text,
    #: 通常在输入框旁边; 用户可通过 config.locators.emoji_button 精确配置)
    _EMOJI_BUTTON_CANDIDATES: tuple[dict, ...] = (
        dict(description="表情"),
        dict(descriptionContains="表情"),
        dict(description="emoji"),
        dict(descriptionContains="emoji"),
    )

    #: 收藏表情 tab 候选 (通常为面板底部/顶部的 tab 栏)
    _STICKER_FAVORITE_TAB_CANDIDATES: tuple[dict, ...] = (
        dict(text="收藏"),
        dict(description="收藏"),
        dict(descriptionContains="收藏"),
    )

    #: 收藏表情面板 grid 容器候选
    _STICKER_GRID_CANDIDATES: tuple[dict, ...] = (
        dict(className="androidx.recyclerview.widget.RecyclerView"),
        dict(className="android.widget.GridView"),
    )

    def open_emoji_panel(self, timeout_s: float = 3.0) -> None:
        """
        点输入区 emoji 按钮打开表情面板. 幂等: 面板已开则直接返回.

        判定"面板已开": 界面上存在 grid (RecyclerView/GridView) 且
        其中可见 "收藏" tab 或大量小尺寸 ImageView.
        """
        # 幂等: 已看到"收藏" tab → 视为已开
        if self._first_existing(self._STICKER_FAVORITE_TAB_CANDIDATES):
            logger.debug("open_emoji_panel: 已见收藏 tab, 视为已开")
            return

        # 若语音模式, 先切文字 (emoji 按钮通常与文字模式共存)
        if not self.dev(resourceId=self.loc.input_edit).exists:
            try:
                self.enter_text_mode()
            except NavigationError:
                pass  # 有些界面即使无 input_edit 也能开 emoji, 忽略

        # 1) 用户显式配置 resource-id 优先
        btn = None
        if self.loc.emoji_button:
            el = self.dev(resourceId=self.loc.emoji_button)
            if el.exists:
                btn = el
        # 2) description 兜底候选
        if not btn:
            btn = self._first_existing(self._EMOJI_BUTTON_CANDIDATES)
        if not btn:
            self._dump("open_emoji_panel_MISS", "找不到 emoji 表情按钮")
            raise NavigationError(
                "找不到 emoji 表情按钮; 请把 resource-id 填到 "
                "config.locators.emoji_button; UI 已 dump"
            )
        btn.click()

        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self._first_existing(self._STICKER_FAVORITE_TAB_CANDIDATES):
                logger.debug("open_emoji_panel: 表情面板已展开")
                return
            time.sleep(0.2)
        self._dump("open_emoji_panel_no_tab", "点击后未见收藏 tab")
        raise NavigationError("emoji 面板加载超时 (未见收藏 tab)")

    def switch_to_favorite_stickers(self, timeout_s: float = 2.0) -> None:
        """切换到"收藏" tab (幂等: 已在收藏 tab 也不报错)."""
        tab = self._first_existing(self._STICKER_FAVORITE_TAB_CANDIDATES)
        if not tab:
            self._dump("switch_favorite_MISS", "找不到收藏 tab")
            raise NavigationError("找不到 emoji 面板 '收藏' tab")
        tab.click()
        time.sleep(0.6)
        # 等 grid 出现
        deadline = time.perf_counter() + timeout_s
        while time.perf_counter() < deadline:
            if self._first_existing(self._STICKER_GRID_CANDIDATES):
                logger.debug("switch_to_favorite_stickers: 收藏 grid 已加载")
                return
            time.sleep(0.15)
        # 不强制报错: 有些版本没有独立 grid, 直接列在整块面板里
        logger.debug(
            "switch_to_favorite_stickers: 未见 grid, 继续 (依赖后续 pick 验证)"
        )

    # ------- Locator 语法 ------- #
    #: 前缀
    _STICKER_LOCATOR_IDX_PREFIX: str = "idx:"
    _STICKER_LOCATOR_DESC_PREFIX: str = "desc:"

    @classmethod
    def _parse_sticker_locator(cls, locator: str) -> tuple[str, str]:
        """
        解析 sticker locator, 返回 (mode, value):
            "idx:3"   → ("idx", "3")
            "3"       → ("idx", "3")   (纯数字视同 idx)
            "desc:xx" → ("desc", "xx")

        非法输入抛 ValueError.
        """
        s = locator.strip()
        if not s:
            raise ValueError("sticker locator 不能为空")
        if s.startswith(cls._STICKER_LOCATOR_IDX_PREFIX):
            val = s[len(cls._STICKER_LOCATOR_IDX_PREFIX):].strip()
            if not val.isdigit():
                raise ValueError(f"idx: 后应跟非负整数, got {val!r}")
            return ("idx", val)
        if s.startswith(cls._STICKER_LOCATOR_DESC_PREFIX):
            val = s[len(cls._STICKER_LOCATOR_DESC_PREFIX):].strip()
            if not val:
                raise ValueError("desc: 后不能为空")
            return ("desc", val)
        if s.isdigit():
            return ("idx", s)
        raise ValueError(
            f"未知 sticker locator 语法: {locator!r}; "
            f"支持 'idx:N' / 纯数字 / 'desc:XXX'"
        )

    def pick_sticker_by_locator(self, locator: str) -> None:
        """
        按 locator 语法在当前 (已切到收藏 tab) 的表情面板中选中一张表情.

        idx 模式: 遍历 grid 内所有 ImageView 类节点, 按 (y, x) 排序取第 N 个
        desc 模式: 找 content-desc 包含子串的节点点击

        Raises:
            NavigationError: 定位失败
            ValueError: locator 语法非法
        """
        mode, value = self._parse_sticker_locator(locator)
        logger.debug(f"pick_sticker_by_locator: mode={mode} value={value!r}")

        if mode == "desc":
            for sel in (
                dict(description=value),
                dict(descriptionContains=value),
            ):
                el = self.dev(**sel)
                if el.exists:
                    el.click()
                    time.sleep(0.5)
                    logger.debug(
                        f"pick_sticker_by_locator: desc 命中 {value!r}"
                    )
                    return
            self._dump(
                "pick_sticker_desc_MISS",
                f"desc {value!r} 未命中",
            )
            raise NavigationError(f"表情面板中未找到 desc={value!r}")

        # idx 模式: 从 UI dump 挑第 N 个可能的表情缩略图
        idx = int(value)
        thumb = self._nth_sticker_thumb(idx)
        if not thumb:
            self._dump(
                "pick_sticker_idx_MISS",
                f"第 {idx} 张表情不存在",
            )
            raise NavigationError(
                f"表情面板中第 {idx} 张表情不存在 (0-indexed)"
            )
        thumb.click()
        time.sleep(0.5)
        logger.debug(f"pick_sticker_by_locator: idx={idx} 已点击")

    def _nth_sticker_thumb(self, idx: int):
        """
        从 UI dump 中挑第 N 张表情缩略图 (按 y, x 排序).

        启发式判定"表情缩略图":
          - class 含 ImageView 或 ViewGroup
          - clickable=true
          - 宽/高在 80~400px 之间
          - 长宽比接近 1:1 (0.5 ~ 2.0)
          - 位于 grid 容器 (RecyclerView/GridView) 内
        """
        try:
            xml_str = self.dev.dump_hierarchy()
        except Exception:
            return None
        root = ET.fromstring(xml_str)

        # 找 grid 容器
        grid_node = None
        for node in root.iter("node"):
            cls = node.attrib.get("class", "")
            if ("RecyclerView" in cls or "GridView" in cls):
                grid_node = node
                break
        if grid_node is None:
            return None

        candidates: list[tuple[int, int, int, int]] = []
        for child in grid_node.iter("node"):
            cls = child.attrib.get("class", "")
            if "ImageView" not in cls and "ViewGroup" not in cls:
                continue
            if child.attrib.get("clickable", "false") != "true":
                continue
            bounds = child.attrib.get("bounds", "")
            m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
            if not m:
                continue
            l, t, r, b = map(int, m.groups())
            w, h = r - l, b - t
            if w < 80 or h < 80 or w > 400 or h > 400:
                continue
            ratio = w / h if h else 0
            if ratio < 0.5 or ratio > 2.0:
                continue
            candidates.append((l, t, r, b))

        if idx < 0 or idx >= len(candidates):
            return None

        # 按 (y, x) 排序: 先上后左
        candidates.sort(key=lambda b: (b[1], b[0]))
        l, t, r, b = candidates[idx]
        cx, cy = (l + r) // 2, (t + b) // 2

        class _Tap:
            def __init__(self, dev, x, y):
                self._dev = dev
                self.x, self.y = x, y
            def click(self):
                self._dev.click(self.x, self.y)
        return _Tap(self.dev, cx, cy)

    def send_sticker(
        self,
        locator: str,
        *,
        after_send_s: float = 1.0,
    ) -> None:
        """
        完整"发送收藏表情"链路 (供 StickerSender 调用):

          1) open_emoji_panel()             # 打开 emoji 面板
          2) switch_to_favorite_stickers()  # 切到 "收藏" tab
          3) pick_sticker_by_locator(loc)   # 按 locator 语法选表情 → 点击即发送

        企微收藏表情通常"点击即发送", 没有二次确认弹窗.
        若目标版本有确认弹窗, 后续可在此方法末尾追加 confirm_card_send() 兜底.

        Args:
            locator: AssetEntry.fta_locator, 语法见 pick_sticker_by_locator
            after_send_s: 发送后等 UI 稳定的秒数
        """
        logger.info(f"send_sticker: 发送 locator={locator!r}")
        self.open_emoji_panel()
        self.switch_to_favorite_stickers()
        self.pick_sticker_by_locator(locator)
        time.sleep(after_send_s)
        logger.info(f"send_sticker: 完成 {locator!r}")
