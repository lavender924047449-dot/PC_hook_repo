"""素材库面板：查看、筛选、维护素材。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import resolve_path
from app.messaging.asset_library import FORWARD_ONLY_TYPES, LOCAL_SOURCE_TYPES
from app.messaging.types import MessageType
from app.messaging import AssetLibrary

TYPE_LABEL = {
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


class AssetLibraryPanel(QWidget):
    status = Signal(str)
    error = Signal(str)
    #: 素材库发生增/删/改/保存/切库 → 通知外部刷新（例如 PlanEditor 的 tag 下拉）
    library_changed = Signal()

    def __init__(self, library_path: str | Path | None = None, parent=None) -> None:
        super().__init__(parent)
        self._library_path = resolve_path(library_path or AssetLibrary.DEFAULT_PATH)
        self._lib = AssetLibrary.load(self._library_path)
        self._build_ui()
        self.refresh_table()

    @property
    def library_path(self) -> Path:
        return self._library_path

    def set_library_path(self, p: str | Path) -> None:
        self._library_path = resolve_path(p)
        self._lib = AssetLibrary.load(self._library_path)
        self.refresh_table()
        self.library_changed.emit()

    def refresh_table(self) -> None:
        rows = sorted(self._lib.all(), key=lambda e: (e.semantic_type.value, e.tag))
        rows = self._filter_rows(rows)
        self._table.setRowCount(len(rows))
        for i, e in enumerate(rows):
            self._set_row(i, [
                e.tag,
                e.semantic_type.value,
                e.display_name or "",
                e.source_path or "",
                e.fta_locator or "",
                e.last_refreshed_at or "",
                e.created_at or "",
            ])
        self._table.resizeColumnsToContents()
        self._status_label.setText(f"显示 {len(rows)} / 共 {len(self._lib)} 条")

    def save_library(self) -> None:
        path = self._lib.save()
        self.status.emit(f"已保存素材库: {path}")
        self.library_changed.emit()

    def add_forward_entry(
        self,
        semantic_type: MessageType,
        fta_locator: str,
        display_name: str | None = None,
    ) -> str:
        e = self._lib.register_forward(
            semantic_type=semantic_type,
            fta_locator=fta_locator,
            display_name=display_name,
            overwrite=True,
        )
        self.refresh_table()
        self.status.emit(f"已添加: {e.tag}")
        self.library_changed.emit()
        return e.tag

    def add_local_entry(
        self,
        semantic_type: MessageType,
        source_path: str | Path,
        display_name: str | None = None,
        fta_locator: str | None = None,
    ) -> str:
        e = self._lib.register_local(
            source_path=source_path,
            semantic_type=semantic_type,
            display_name=display_name,
            fta_locator=fta_locator,
            overwrite=True,
        )
        self.refresh_table()
        self.status.emit(f"已添加: {e.tag}")
        self.library_changed.emit()
        return e.tag

    def update_entry(
        self,
        tag: str,
        *,
        display_name: str | None = None,
        fta_locator: str | None = None,
    ) -> None:
        e = self._lib.get(tag)
        e.display_name = display_name or None
        e.fta_locator = fta_locator or None
        self.refresh_table()
        self.status.emit(f"已更新: {tag}")
        self.library_changed.emit()

    def remove_entry(self, tag: str) -> None:
        self._lib.remove(tag)
        self.refresh_table()
        self.status.emit(f"已删除: {tag}")
        self.library_changed.emit()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        top = QGridLayout()
        top.addWidget(QLabel("素材库文件路径:"), 0, 0)
        self._path_edit = QLineEdit(str(self._library_path))
        top.addWidget(self._path_edit, 0, 1)
        self._btn_apply_path = QPushButton("切换路径")
        self._btn_apply_path.clicked.connect(self._on_apply_path)
        top.addWidget(self._btn_apply_path, 0, 2)
        root.addLayout(top)

        filters = QGridLayout()
        filters.addWidget(QLabel("类型筛选:"), 0, 0)
        self._type_filter = QComboBox()
        self._type_filter.addItem("全部", userData="")
        for t in sorted(MessageType, key=lambda x: x.value):
            if t is MessageType.TEXT:
                continue
            self._type_filter.addItem(TYPE_LABEL[t], userData=t.value)
        filters.addWidget(self._type_filter, 0, 1)
        filters.addWidget(QLabel("搜索关键字:"), 0, 2)
        self._keyword_edit = QLineEdit("")
        self._keyword_edit.setPlaceholderText("匹配 素材编码 / 显示名称 / 文件路径 / 定位词")
        filters.addWidget(self._keyword_edit, 0, 3)
        root.addLayout(filters)

        btns = QHBoxLayout()
        self._btn_reload = QPushButton("刷新")
        self._btn_save = QPushButton("保存")
        self._btn_add_local = QPushButton("添加本地素材")
        self._btn_add_forward = QPushButton("添加转发素材")
        self._btn_edit = QPushButton("编辑当前项")
        self._btn_delete = QPushButton("删除当前项")
        self._btn_export_tags = QPushButton("导出可见素材编码")
        for b in (
            self._btn_reload,
            self._btn_save,
            self._btn_add_local,
            self._btn_add_forward,
            self._btn_edit,
            self._btn_delete,
            self._btn_export_tags,
        ):
            btns.addWidget(b)
        btns.addStretch(1)
        root.addLayout(btns)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels([
            "素材编码",
            "类型",
            "显示名称",
            "本地文件",
            "定位词",
            "last_refreshed_at",
            "created_at",
        ])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        root.addWidget(self._table, 1)

        self._status_label = QLabel("显示 0 / 共 0 条")
        root.addWidget(self._status_label)

        self._btn_reload.clicked.connect(self._on_reload)
        self._btn_save.clicked.connect(self._on_save)
        self._btn_add_local.clicked.connect(self._on_add_local)
        self._btn_add_forward.clicked.connect(self._on_add_forward)
        self._btn_edit.clicked.connect(self._on_edit_selected)
        self._btn_delete.clicked.connect(self._on_delete_selected)
        self._btn_export_tags.clicked.connect(self._on_export_visible_tags)
        self._type_filter.currentIndexChanged.connect(lambda _i: self.refresh_table())
        self._keyword_edit.textChanged.connect(lambda _t: self.refresh_table())

    def _set_row(self, row: int, vals: list[str]) -> None:
        for col, v in enumerate(vals):
            self._table.setItem(row, col, QTableWidgetItem(v))

    def _on_apply_path(self) -> None:
        p = self._path_edit.text().strip()
        if not p:
            return
        self.set_library_path(p)
        self.status.emit(f"切换素材库: {self._library_path}")

    def _on_reload(self) -> None:
        self._lib = AssetLibrary.load(self._library_path)
        self.refresh_table()
        self.status.emit("素材库已刷新")
        self.library_changed.emit()

    def _on_save(self) -> None:
        try:
            self.save_library()
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "保存失败", self._guide(str(e)))

    def _on_add_local(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "选择本地素材文件", "", "所有文件 (*.*)")
        if not p:
            return
        type_text, ok = QInputDialog.getItem(
            self,
            "选择语义类型",
            "本地素材类型:",
            [TYPE_LABEL[t] for t in sorted(LOCAL_SOURCE_TYPES, key=lambda x: x.value)],
            0,
            False,
        )
        if not ok:
            return
        display, _ = QInputDialog.getText(self, "显示名", "display_name（可空）:")
        loc, _ = QInputDialog.getText(self, "FTA 定位", "定位词（可空）:")
        try:
            self.add_local_entry(
                semantic_type=self._message_type_from_label(type_text),
                source_path=p,
                display_name=(display or "").strip() or None,
                fta_locator=(loc or "").strip() or None,
            )
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "添加失败", self._guide(str(e)))

    def _on_add_forward(self) -> None:
        type_text, ok = QInputDialog.getItem(
            self,
            "选择语义类型",
            "转发素材类型:",
            [TYPE_LABEL[t] for t in sorted(FORWARD_ONLY_TYPES, key=lambda x: x.value)],
            0,
            False,
        )
        if not ok:
            return
        loc, ok = QInputDialog.getText(self, "FTA 定位", "定位词（必填）:")
        if not ok:
            return
        display, _ = QInputDialog.getText(self, "显示名", "display_name（可空）:")
        try:
            self.add_forward_entry(
                semantic_type=self._message_type_from_label(type_text),
                fta_locator=(loc or "").strip(),
                display_name=(display or "").strip() or None,
            )
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "添加失败", self._guide(str(e)))

    def _selected_tag(self) -> str | None:
        row = self._table.currentRow()
        if row < 0:
            return None
        cell = self._table.item(row, 0)
        return cell.text().strip() if cell else None

    def _on_edit_selected(self) -> None:
        tag = self._selected_tag()
        if not tag:
            QMessageBox.information(self, "提示", "请先选中一条素材")
            return
        entry = self._lib.get(tag)
        display, ok = QInputDialog.getText(
            self, "编辑 display_name", "display_name:", text=entry.display_name or ""
        )
        if not ok:
            return
        loc, ok = QInputDialog.getText(
            self, "编辑定位词", "定位词:", text=entry.fta_locator or ""
        )
        if not ok:
            return
        try:
            self.update_entry(
                tag,
                display_name=(display or "").strip() or None,
                fta_locator=(loc or "").strip() or None,
            )
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "更新失败", self._guide(str(e)))

    def _on_delete_selected(self) -> None:
        tag = self._selected_tag()
        if not tag:
            QMessageBox.information(self, "提示", "请先选中一条素材")
            return
        ans = QMessageBox.question(self, "确认删除", f"确认删除素材 `{tag}` 吗？")
        if ans != QMessageBox.StandardButton.Yes:
            return
        try:
            self.remove_entry(tag)
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "删除失败", self._guide(str(e)))

    def _filter_rows(self, rows):
        type_key = self._type_filter.currentData()
        kw = self._keyword_edit.text().strip().lower()

        def _matched(e) -> bool:
            if type_key and e.semantic_type.value != type_key:
                return False
            if not kw:
                return True
            text = " | ".join([
                e.tag,
                e.semantic_type.value,
                e.display_name or "",
                e.source_path or "",
                e.fta_locator or "",
            ]).lower()
            return kw in text

        return [e for e in rows if _matched(e)]

    def visible_tags(self) -> list[str]:
        tags: list[str] = []
        for r in range(self._table.rowCount()):
            item = self._table.item(r, 0)
            if item:
                tags.append(item.text())
        return tags

    def _on_export_visible_tags(self) -> None:
        tags = self.visible_tags()
        if not tags:
            QMessageBox.information(self, "提示", "当前没有可导出的素材编码")
            return

        default = str(self.library_path.parent / "asset_tags.txt")
        out, _ = QFileDialog.getSaveFileName(
            self,
            "导出可见素材编码",
            default,
            "文本文件 (*.txt);;所有文件 (*.*)",
        )
        if not out:
            return
        p = Path(out)
        p.write_text("\n".join(tags) + "\n", encoding="utf-8")

        QApplication.clipboard().setText("\n".join(tags))
        self.status.emit(f"已导出 {len(tags)} 个素材编码: {p}（并已复制到剪贴板）")

    @staticmethod
    def _guide(msg: str) -> str:
        return f"{msg}\n\n你可以这样做：\n1) 检查输入内容是否完整\n2) 重新点击“刷新”后再试\n3) 若仍失败，请查看日志"

    @staticmethod
    def _message_type_from_label(label: str) -> MessageType:
        for t, text in TYPE_LABEL.items():
            if text == label:
                return t
        return MessageType(label)

