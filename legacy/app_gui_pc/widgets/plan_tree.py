"""
任务树视图（只读）。

结构:
    BatchPlan
      ├── Task 1 · label · N 联系人 · M 消息
      │     ├── 📇 联系人 (N)
      │     │     ├── 张三
      │     │     └── ...
      │     └── 💬 消息序列 (M)
      │           ├── [1] text('周末愉快')  ⏱ 3–6s
      │           ├── [2] miniprogram(#mp_xxx)  ⏱ 12–22s
      │           └── ...
      └── ...

设计:
    * 只读展示 (5.2 才做编辑).
    * 用 QTreeWidget (轻量, 无需自定义 model, 5.1 够用).
    * `populate(plan)` 幂等: 可反复调用来切换 plan.
    * 提供 `plan_summary(plan)` 顶栏一句话.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

if TYPE_CHECKING:
    from app.messaging.plan import BatchPlan, BroadcastTask
    from app.messaging.types import Message


# 消息类型 → emoji (轻量视觉锚点; 无 emoji 也不会崩)
_TYPE_ICON = {
    "text": "📝",
    "image": "🖼",
    "video": "🎬",
    "file": "📎",
    "voice": "🎙",
    "contact_card": "👤",
    "location": "📍",
    "sticker": "😀",
    "miniprogram": "🧩",
    "channel_video": "📺",
}


class PlanTreeWidget(QTreeWidget):
    """
    只读展示 BatchPlan 的树形控件.

    调用:
        w = PlanTreeWidget()
        w.populate(plan)   # 或 w.clear() 清空
    """

    #: 顶层节点在 UserRole 里存储的 kind 值
    ROLE_KIND = Qt.ItemDataRole.UserRole + 1
    KIND_TASK = "task"
    KIND_CONTACTS = "contacts"
    KIND_MESSAGES = "messages"
    KIND_CONTACT = "contact"
    KIND_MESSAGE = "message"

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setHeaderLabels(["条目", "详情"])
        self.setColumnWidth(0, 320)
        self.setUniformRowHeights(True)
        self.setAlternatingRowColors(True)

    # ---------- API ---------- #

    def populate(self, plan: "BatchPlan | None") -> None:
        """加载/切换 plan; 传 None 清空."""
        self.clear()
        if plan is None:
            return
        for i, task in enumerate(plan.tasks, 1):
            self.addTopLevelItem(self._build_task_item(i, task, plan))
        self.expandToDepth(0)  # 默认展开一层, 看得到 Task 摘要

    # ---------- 构造 ---------- #

    def _build_task_item(
        self,
        idx: int,
        task: "BroadcastTask",
        plan: "BatchPlan",
    ) -> QTreeWidgetItem:
        label = task.label or "(无标签)"
        title = f"任务 {idx} · {label}"
        detail = f"{len(task.contacts)} 联系人 · {len(task.messages)} 消息"
        item = QTreeWidgetItem([title, detail])
        item.setData(0, self.ROLE_KIND, self.KIND_TASK)

        # -- 联系人子组 --
        contacts_head = QTreeWidgetItem([
            f"📇 联系人 ({len(task.contacts)})",
            "",
        ])
        contacts_head.setData(0, self.ROLE_KIND, self.KIND_CONTACTS)
        for c in task.contacts:
            ci = QTreeWidgetItem([c, ""])
            ci.setData(0, self.ROLE_KIND, self.KIND_CONTACT)
            contacts_head.addChild(ci)
        item.addChild(contacts_head)

        # -- 消息子组 --
        msgs_head = QTreeWidgetItem([
            f"💬 消息序列 ({len(task.messages)})",
            "",
        ])
        msgs_head.setData(0, self.ROLE_KIND, self.KIND_MESSAGES)
        for j, msg in enumerate(task.messages, 1):
            msgs_head.addChild(self._build_message_item(j, msg, plan))
        item.addChild(msgs_head)

        return item

    def _build_message_item(
        self,
        idx: int,
        msg: "Message",
        plan: "BatchPlan",
    ) -> QTreeWidgetItem:
        icon = _TYPE_ICON.get(msg.type.value, "•")
        title = f"[{idx}] {icon} {msg.brief()}"
        lo, hi = plan.intervals.get(msg.type)
        detail = f"⏱ {lo:g}–{hi:g}s"
        item = QTreeWidgetItem([title, detail])
        item.setData(0, self.ROLE_KIND, self.KIND_MESSAGE)
        return item


# ---------- 顶栏一句话摘要 (给 MainWindow 用) ---------- #

def plan_summary(plan: "BatchPlan | None") -> str:
    if plan is None:
        return "尚未加载任务方案"
    return (
        f"{plan.meta.name}  ·  "
        f"任务数={len(plan.tasks)}  "
        f"对象数={len(plan.unique_contacts())}  "
        f"消息数={plan.total_messages()}  "
        f"预计发送={plan.total_sends()}"
    )
