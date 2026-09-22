"""Step 5.1: 素材库页签（列表 + label 行内编辑）。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.broadcast.library import VoiceLibrary, VoiceLibraryEntry


class TaggerPanel(QWidget):
    """展示语音素材并允许直接修改 label。"""

    library_changed = Signal()

    _COL_ID = 0
    _COL_FILE = 1
    _COL_DURATION = 2
    _COL_NOTE = 3
    _COL_LABEL = 4
    _COL_USAGE = 5
    _COL_CAPTURED = 6

    def __init__(self, *, index_path: str | Path | None = None) -> None:
        super().__init__()
        self._index_path = index_path
        self._updating = False
        self._library = VoiceLibrary.load(index_path)
        self._entries: list[VoiceLibraryEntry] = []
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        self._stats = QLabel("素材数: 0")
        self._btn_refresh = QPushButton("刷新")
        bar.addWidget(self._stats)
        bar.addStretch(1)
        bar.addWidget(self._btn_refresh)
        root.addLayout(bar)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(
            ["ID", "文件", "时长(s)", "备注", "标签", "使用次数", "采集时间"]
        )
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.DoubleClicked
            | QTableWidget.EditTrigger.SelectedClicked
            | QTableWidget.EditTrigger.EditKeyPressed
        )
        self._table.horizontalHeader().setStretchLastSection(True)
        root.addWidget(self._table, 1)

        self._btn_refresh.clicked.connect(self.refresh)
        self._table.itemChanged.connect(self._on_item_changed)

    def refresh(self) -> None:
        self._library = VoiceLibrary.load(self._index_path)
        self._entries = self._library.list()
        stats = self._library.stats()
        self._stats.setText(
            f"素材数: {stats['total']} | 已打标签: {stats['labeled']} | 未打标签: {stats['unlabeled']}"
        )

        self._updating = True
        try:
            self._table.setRowCount(len(self._entries))
            for row, entry in enumerate(self._entries):
                self._set_row(row, entry)
        finally:
            self._updating = False
        self.library_changed.emit()

    def entries(self) -> list[VoiceLibraryEntry]:
        return list(self._entries)

    def _set_row(self, row: int, entry: VoiceLibraryEntry) -> None:
        id_item = QTableWidgetItem(entry.id)
        id_item.setFlags(id_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, self._COL_ID, id_item)

        file_item = QTableWidgetItem(entry.file)
        file_item.setFlags(file_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, self._COL_FILE, file_item)

        duration_item = QTableWidgetItem(str(entry.duration))
        duration_item.setFlags(duration_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, self._COL_DURATION, duration_item)

        note_item = QTableWidgetItem(entry.note)
        note_item.setFlags(note_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, self._COL_NOTE, note_item)

        label_item = QTableWidgetItem(entry.label)
        label_item.setFlags(label_item.flags() | Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, self._COL_LABEL, label_item)

        usage_item = QTableWidgetItem(str(entry.usage_count))
        usage_item.setFlags(usage_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, self._COL_USAGE, usage_item)

        captured_item = QTableWidgetItem(entry.captured_at)
        captured_item.setFlags(captured_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self._table.setItem(row, self._COL_CAPTURED, captured_item)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._updating:
            return
        if item.column() != self._COL_LABEL:
            return
        row = item.row()
        if row < 0 or row >= len(self._entries):
            return
        entry = self._entries[row]
        new_label = item.text().strip()
        if new_label == entry.label:
            return
        self._library.update_label(entry.id, new_label)
        self._library.save()
        self.refresh()
