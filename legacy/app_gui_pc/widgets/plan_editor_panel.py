"""任务编辑面板：JSON + 可视化联动。"""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.messaging import (
    AssetLibrary,
    BatchPlan,
    BroadcastTask,
    Message,
    MessageType,
    load_plan,
    save_plan,
)

TAG_MESSAGE_TYPES = (
    MessageType.MINIPROGRAM,
    MessageType.CHANNEL_VIDEO,
    MessageType.LOCATION,
    MessageType.STICKER,
)

TYPE_LABEL = {
    MessageType.TEXT: "文本",
    MessageType.IMAGE: "图片",
    MessageType.VIDEO: "视频",
    MessageType.FILE: "文件",
    MessageType.VOICE: "语音",
    MessageType.CONTACT_CARD: "名片",
    MessageType.LOCATION: "位置",
    MessageType.STICKER: "表情",
    MessageType.MINIPROGRAM: "小程序",
    MessageType.CHANNEL_VIDEO: "视频号",
}


class PlanEditorPanel(QWidget):
    status = Signal(str)
    error = Signal(str)
    plan_applied = Signal(object)  # BatchPlan
    plan_saved = Signal(str)

    def __init__(
        self,
        plan: BatchPlan | None = None,
        library_path: str | Path | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._library_path = Path(library_path) if library_path else None
        self._model: BatchPlan | None = None
        self._ui_syncing = False

        self._build_ui()
        self._load_tags()

        if plan is not None:
            self.set_plan(plan)
        else:
            self._on_new_template()

    # ---------- 外部 API ---------- #

    def set_plan(self, plan: BatchPlan) -> None:
        self._model = BatchPlan.model_validate(plan.model_dump(mode="json"))
        self._sync_editor_from_model()
        self._rebuild_form_indices()

    def to_plan(self) -> BatchPlan:
        raw = self._editor.toPlainText().strip()
        if not raw:
            raise ValueError("编辑区为空")
        data = json.loads(raw)
        return BatchPlan.model_validate(data)

    # ---------- UI ---------- #

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        bar = QHBoxLayout()
        self._btn_pretty = QPushButton("格式化")
        self._btn_apply = QPushButton("应用当前内容")
        self._btn_open = QPushButton("打开任务文件")
        self._btn_save = QPushButton("另存任务文件")
        self._btn_template = QPushButton("新建模板")
        self._btn_reload_tags = QPushButton("刷新素材标签")
        for b in (
            self._btn_pretty,
            self._btn_apply,
            self._btn_open,
            self._btn_save,
            self._btn_template,
            self._btn_reload_tags,
        ):
            bar.addWidget(b)
        bar.addStretch(1)
        root.addLayout(bar)

        # ---- 可视化表单区 ----
        form = QGridLayout()
        form.addWidget(QLabel("任务:"), 0, 0)
        self._task_combo = QComboBox()
        form.addWidget(self._task_combo, 0, 1)
        self._btn_add_task = QPushButton("+任务")
        self._btn_del_task = QPushButton("-任务")
        form.addWidget(self._btn_add_task, 0, 2)
        form.addWidget(self._btn_del_task, 0, 3)

        form.addWidget(QLabel("任务名称:"), 1, 0)
        self._task_label_edit = QLineEdit()
        self._task_label_edit.setPlaceholderText("任务标签")
        form.addWidget(self._task_label_edit, 1, 1, 1, 3)

        form.addWidget(QLabel("发送对象(逗号分隔):"), 2, 0)
        self._contacts_edit = QLineEdit()
        self._contacts_edit.setPlaceholderText("张三,李四,王五")
        form.addWidget(self._contacts_edit, 2, 1, 1, 3)

        form.addWidget(QLabel("消息序号:"), 3, 0)
        self._msg_combo = QComboBox()
        form.addWidget(self._msg_combo, 3, 1)
        self._btn_add_msg = QPushButton("+消息")
        self._btn_del_msg = QPushButton("-消息")
        self._btn_msg_up = QPushButton("上移")
        self._btn_msg_down = QPushButton("下移")
        form.addWidget(self._btn_add_msg, 3, 2)
        form.addWidget(self._btn_del_msg, 3, 3)
        form.addWidget(self._btn_msg_up, 3, 4)
        form.addWidget(self._btn_msg_down, 3, 5)

        form.addWidget(QLabel("消息类型:"), 4, 0)
        self._msg_type_combo = QComboBox()
        for t in MessageType:
            self._msg_type_combo.addItem(TYPE_LABEL[t], userData=t.value)
        form.addWidget(self._msg_type_combo, 4, 1)

        form.addWidget(QLabel("消息内容:"), 4, 2)
        self._msg_value_edit = QLineEdit()
        self._msg_value_edit.setPlaceholderText("文本内容 / 文件路径 / 素材编码 / 名片对象")
        form.addWidget(self._msg_value_edit, 4, 3)

        self._btn_sync_from_json = QPushButton("从文本同步到表单")
        self._btn_sync_to_json = QPushButton("从表单同步到文本")
        form.addWidget(self._btn_sync_from_json, 5, 2)
        form.addWidget(self._btn_sync_to_json, 5, 3)

        root.addLayout(form)

        # ---- tag 联动区 ----
        insert_row = QGridLayout()
        insert_row.addWidget(QLabel("快速插入素材消息:"), 0, 0)
        self._type_combo = QComboBox()
        for t in TAG_MESSAGE_TYPES:
            self._type_combo.addItem(TYPE_LABEL[t], userData=t.value)
        insert_row.addWidget(self._type_combo, 0, 1)
        self._tag_combo = QComboBox()
        insert_row.addWidget(self._tag_combo, 0, 2)
        self._btn_insert = QPushButton("插入消息片段")
        self._btn_copy = QPushButton("复制素材编码")
        self._btn_use_tag_in_value = QPushButton("写入当前消息内容")
        insert_row.addWidget(self._btn_insert, 0, 3)
        insert_row.addWidget(self._btn_copy, 0, 4)
        insert_row.addWidget(self._btn_use_tag_in_value, 0, 5)
        root.addLayout(insert_row)

        self._editor = QTextEdit()
        self._editor.setPlaceholderText(
            "在这里编辑任务 JSON。点击“应用当前内容”后会校验并刷新页面。"
        )
        root.addWidget(self._editor, 1)

        self._status_label = QLabel("就绪")
        root.addWidget(self._status_label)

        # signals
        self._btn_pretty.clicked.connect(self._on_pretty)
        self._btn_apply.clicked.connect(self._on_apply)
        self._btn_open.clicked.connect(self._on_open)
        self._btn_save.clicked.connect(self._on_save)
        self._btn_template.clicked.connect(self._on_new_template)
        self._btn_reload_tags.clicked.connect(self._load_tags)

        self._btn_insert.clicked.connect(self._on_insert_snippet)
        self._btn_copy.clicked.connect(self._on_copy_tag)
        self._btn_use_tag_in_value.clicked.connect(self._on_use_tag_in_value)
        self._type_combo.currentIndexChanged.connect(self._load_tags)

        self._btn_sync_from_json.clicked.connect(self._on_sync_from_json)
        self._btn_sync_to_json.clicked.connect(self._on_sync_to_json)
        self._btn_add_task.clicked.connect(self._on_add_task)
        self._btn_del_task.clicked.connect(self._on_del_task)
        self._btn_add_msg.clicked.connect(self._on_add_msg)
        self._btn_del_msg.clicked.connect(self._on_del_msg)
        self._btn_msg_up.clicked.connect(self._on_move_msg_up)
        self._btn_msg_down.clicked.connect(self._on_move_msg_down)

        self._task_combo.currentIndexChanged.connect(self._on_task_changed)
        self._msg_combo.currentIndexChanged.connect(self._on_msg_changed)
        self._msg_type_combo.currentIndexChanged.connect(self._on_msg_type_changed)

    # ---------- 素材标签 ---------- #

    def _asset_library(self) -> AssetLibrary:
        return AssetLibrary.load(self._library_path)

    def _load_tags(self) -> None:
        t = MessageType(self._type_combo.currentData())
        lib = self._asset_library()
        entries = sorted(lib.by_type(t), key=lambda e: e.tag)

        prev_tag = self._tag_combo.currentData()
        self._tag_combo.clear()
        for e in entries:
            label = e.tag
            if e.display_name:
                label += f" · {e.display_name}"
            self._tag_combo.addItem(label, userData=e.tag)
        # 尽量保留原先选中的 tag, 避免联动刷新时用户当前选项被打散
        if prev_tag is not None:
            for i in range(self._tag_combo.count()):
                if self._tag_combo.itemData(i) == prev_tag:
                    self._tag_combo.setCurrentIndex(i)
                    break
        self._status(f"已加载 {len(entries)} 个 {t.value} 素材编码")

    # 供外部（例如 MainWindow 收到 AssetLibraryPanel.library_changed 信号）调用
    def reload_asset_tags(self) -> None:
        self._load_tags()

    # ---------- 状态 ---------- #

    def _status(self, msg: str) -> None:
        self._status_label.setText(msg)
        self.status.emit(msg)

    @staticmethod
    def _guide(msg: str) -> str:
        return f"{msg}\n\n你可以这样做：\n1) 检查当前输入是否完整\n2) 点击“格式化”后再试\n3) 必要时回到模板重新编辑"

    # ---------- JSON 主流程 ---------- #

    def _on_pretty(self) -> None:
        try:
            plan = self.to_plan()
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "格式化失败", self._guide(str(e)))
            return
        self.set_plan(plan)
        self._status("已格式化并校验")

    def _on_apply(self) -> None:
        if self._model is not None:
            self._write_task_fields()
            if not self._write_msg_fields():
                return
            self._sync_editor_from_model()
        try:
            plan = self.to_plan()
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "应用失败", self._guide(str(e)))
            return
        self.plan_applied.emit(plan)
        self._status("已应用到当前窗口")

    def _on_open(self) -> None:
        p, _ = QFileDialog.getOpenFileName(
            self,
            "打开任务文件",
            "samples",
            "任务文件 (*.json);;所有文件 (*.*)",
        )
        if not p:
            return
        try:
            plan = load_plan(p)
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "打开失败", self._guide(str(e)))
            return
        self.set_plan(plan)
        self._status(f"已打开: {Path(p).name}")

    def _on_save(self) -> None:
        if self._model is not None:
            self._write_task_fields()
            if not self._write_msg_fields():
                return
            self._sync_editor_from_model()
        try:
            plan = self.to_plan()
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "保存失败", self._guide(str(e)))
            return
        p, _ = QFileDialog.getSaveFileName(
            self,
            "另存任务文件",
            "runtime/任务方案_编辑后.json",
            "任务文件 (*.json);;所有文件 (*.*)",
        )
        if not p:
            return
        out = save_plan(plan, p)
        self.plan_saved.emit(str(out))
        self._status(f"已保存: {out}")

    def _on_new_template(self) -> None:
        template = BatchPlan.model_validate(
            {
                "meta": {"name": "新建任务方案", "note": "默认模板"},
                "tasks": [
                    {
                        "label": "示例任务",
                        "contacts": ["文件传输助手"],
                        "messages": [{"type": "text", "text": "你好"}],
                    }
                ],
            }
        )
        self.set_plan(template)
        self._status("已创建模板")

    # ---------- 插入 / 复制 ---------- #

    def _on_insert_snippet(self) -> None:
        tag = self._tag_combo.currentData()
        if not tag:
            QMessageBox.information(self, "提示", "当前类型没有可用素材编码")
            return
        t = self._type_combo.currentData()
        snippet = json.dumps({"type": t, "tag": tag}, ensure_ascii=False, indent=2)
        cur = self._editor.textCursor()
        cur.insertText(snippet)
        self._status(f"已插入 {t} 片段")

    def _on_copy_tag(self) -> None:
        tag = self._tag_combo.currentData()
        if not tag:
            QMessageBox.information(self, "提示", "当前没有可复制素材编码")
            return
        QApplication.clipboard().setText(str(tag))
        self._status(f"已复制素材编码: {tag}")

    def _on_use_tag_in_value(self) -> None:
        tag = self._tag_combo.currentData()
        if not tag:
            QMessageBox.information(self, "提示", "当前没有可用素材编码")
            return
        self._msg_value_edit.setText(str(tag))
        self._status(f"已写入消息内容: {tag}")

    # ---------- 表单逻辑 ---------- #

    def _on_sync_from_json(self) -> None:
        try:
            self._model = self.to_plan()
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "解析失败", self._guide(str(e)))
            return
        self._rebuild_form_indices()
        self._status("已从 JSON 同步到表单")

    def _on_sync_to_json(self) -> None:
        if self._model is None:
            return
        self._write_task_fields()
        if not self._write_msg_fields():
            return
        try:
            # 借 model_validate 再校验一次
            self._model = BatchPlan.model_validate(self._model.model_dump(mode="json"))
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "校验失败", self._guide(str(e)))
            return
        self._sync_editor_from_model()
        self._status("已从表单同步到 JSON")

    def _rebuild_form_indices(self) -> None:
        if self._model is None:
            return
        self._ui_syncing = True
        try:
            self._task_combo.clear()
            for i, t in enumerate(self._model.tasks, 1):
                label = t.label or "(无标签)"
                self._task_combo.addItem(f"Task {i}: {label}", userData=i - 1)
            if self._task_combo.count() == 0:
                return
            self._task_combo.setCurrentIndex(0)
            self._refresh_task_fields()
            self._refresh_msg_indices()
        finally:
            self._ui_syncing = False

    def _refresh_task_fields(self) -> None:
        task = self._current_task()
        if task is None:
            self._task_label_edit.setText("")
            self._contacts_edit.setText("")
            return
        self._task_label_edit.setText(task.label or "")
        self._contacts_edit.setText(",".join(task.contacts))

    def _refresh_msg_indices(self) -> None:
        task = self._current_task()
        self._msg_combo.clear()
        if task is None:
            self._msg_value_edit.setText("")
            return
        for i, m in enumerate(task.messages, 1):
            self._msg_combo.addItem(f"#{i} {m.brief()}", userData=i - 1)
        if self._msg_combo.count() > 0:
            self._msg_combo.setCurrentIndex(0)
            self._refresh_msg_fields()

    def _refresh_msg_fields(self) -> None:
        msg = self._current_msg()
        if msg is None:
            return
        self._set_combo_value(self._msg_type_combo, msg.type.value)
        self._msg_value_edit.setText(self._msg_value(msg))

    def _current_task_index(self) -> int:
        val = self._task_combo.currentData()
        return int(val) if val is not None else -1

    def _current_msg_index(self) -> int:
        val = self._msg_combo.currentData()
        return int(val) if val is not None else -1

    def _current_task(self):
        if self._model is None:
            return None
        i = self._current_task_index()
        if i < 0 or i >= len(self._model.tasks):
            return None
        return self._model.tasks[i]

    def _current_msg(self):
        task = self._current_task()
        if task is None:
            return None
        i = self._current_msg_index()
        if i < 0 or i >= len(task.messages):
            return None
        return task.messages[i]

    def _msg_value(self, msg) -> str:
        if msg.text:
            return msg.text
        if msg.path:
            return msg.path
        if msg.tag:
            return msg.tag
        if msg.friend_name:
            return msg.friend_name
        return ""

    def _value_key_for_type(self, t: MessageType) -> str:
        if t == MessageType.TEXT:
            return "text"
        if t in (MessageType.IMAGE, MessageType.VIDEO, MessageType.FILE, MessageType.VOICE):
            return "path"
        if t in (MessageType.LOCATION, MessageType.STICKER, MessageType.MINIPROGRAM, MessageType.CHANNEL_VIDEO):
            return "tag"
        if t == MessageType.CONTACT_CARD:
            return "friend_name"
        return "text"

    def _build_msg_dict(self, msg_type: MessageType, value: str) -> dict:
        key = self._value_key_for_type(msg_type)
        data = {"type": msg_type.value}
        if value:
            data[key] = value
        return data

    def _on_task_changed(self, _index: int) -> None:
        if self._ui_syncing:
            return
        self._refresh_task_fields()
        self._refresh_msg_indices()

    def _on_msg_changed(self, _index: int) -> None:
        if self._ui_syncing:
            return
        self._refresh_msg_fields()

    def _on_msg_type_changed(self, _index: int) -> None:
        if self._ui_syncing:
            return
        t = MessageType(self._msg_type_combo.currentData())
        key = self._value_key_for_type(t)
        self._msg_value_edit.setPlaceholderText(key)

    def _write_task_fields(self) -> None:
        task = self._current_task()
        if task is None:
            return
        task.label = (self._task_label_edit.text().strip() or None)
        contacts = [x.strip() for x in self._contacts_edit.text().split(",") if x.strip()]
        # 允许写空: 用户可能在整批替换; 真正的 "至少 1 个联系人" 交给 pydantic 校验
        # (BroadcastTask.contacts min_length=1), 避免旧值静默残留。
        task.contacts = contacts
        if not contacts:
            self._status("⚠ 当前任务 contacts 已清空, 应用/保存前请补至少 1 个")

    def _write_msg_fields(self) -> bool:
        task = self._current_task()
        msg = self._current_msg()
        if task is None or msg is None:
            # 没有当前消息可写不算错; 让后续 pydantic 校验去挡空 messages
            return True
        mi = self._current_msg_index()
        t = MessageType(self._msg_type_combo.currentData())
        v = self._msg_value_edit.text().strip()
        try:
            task.messages[mi] = Message.model_validate(self._build_msg_dict(t, v))
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "消息内容无效", self._guide(str(e)))
            return False
        return True

    def _on_add_task(self) -> None:
        if self._model is None:
            return
        self._model.tasks.append(
            BroadcastTask.model_validate(
                {
                    "label": "新任务",
                    "contacts": ["文件传输助手"],
                    "messages": [{"type": "text", "text": "新消息"}],
                }
            )
        )
        self._rebuild_form_indices()
        self._task_combo.setCurrentIndex(self._task_combo.count() - 1)
        self._status("已新增任务")

    def _on_del_task(self) -> None:
        if self._model is None:
            return
        ti = self._current_task_index()
        if ti < 0:
            return
        self._model.tasks.pop(ti)
        self._rebuild_form_indices()
        if not self._model.tasks:
            # 允许暂时清空; 应用/保存时 pydantic 会挡住 (BatchPlan.tasks min_length=1)
            self._status("⚠ 已删完全部任务, 应用/保存前请至少新增 1 个")
        else:
            self._status("已删除任务")

    def _on_add_msg(self) -> None:
        task = self._current_task()
        if task is None:
            return
        task.messages.append(Message.model_validate({"type": "text", "text": "新消息"}))
        self._refresh_msg_indices()
        self._msg_combo.setCurrentIndex(self._msg_combo.count() - 1)
        self._status("已新增消息")

    def _on_del_msg(self) -> None:
        task = self._current_task()
        if task is None:
            return
        mi = self._current_msg_index()
        if mi < 0:
            return
        task.messages.pop(mi)
        self._refresh_msg_indices()
        if not task.messages:
            # 允许暂时清空; 应用/保存时 pydantic 会挡住 (BroadcastTask.messages min_length=1)
            self._status("⚠ 已删完当前任务的全部消息, 应用/保存前请至少新增 1 条")
        else:
            self._status("已删除消息")

    def _on_move_msg_up(self) -> None:
        self._move_msg(-1)

    def _on_move_msg_down(self) -> None:
        self._move_msg(1)

    def _move_msg(self, delta: int) -> None:
        task = self._current_task()
        if task is None:
            return
        idx = self._current_msg_index()
        if idx < 0:
            return
        new_idx = idx + delta
        if new_idx < 0 or new_idx >= len(task.messages):
            return
        task.messages[idx], task.messages[new_idx] = (
            task.messages[new_idx],
            task.messages[idx],
        )
        self._refresh_msg_indices()
        self._msg_combo.setCurrentIndex(new_idx)
        self._status("已调整消息顺序")

    def _set_combo_value(self, combo: QComboBox, value: str) -> None:
        for i in range(combo.count()):
            if combo.itemData(i) == value:
                combo.setCurrentIndex(i)
                return

    def _sync_editor_from_model(self) -> None:
        if self._model is None:
            return
        payload = self._model.model_dump(mode="json")
        self._editor.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2))

    # 对外可调用: 先把当前表单输入写回 model，再同步 JSON
    def flush_form_to_json(self) -> None:
        self._write_task_fields()
        self._write_msg_fields()
        self._on_sync_to_json()

