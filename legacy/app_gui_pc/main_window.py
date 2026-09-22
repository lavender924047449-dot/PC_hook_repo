"""主窗口：运营向 5 页签界面。"""

from __future__ import annotations

import os
from pathlib import Path

from loguru import logger
from PySide6.QtCore import QThread, Qt
from PySide6.QtGui import QAction, QFont, QFontDatabase, QKeySequence, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.config import load_config, project_root
from app.messaging.plan import BatchPlan, load_plan
from app.pc_wecom.account_map import AccountMapService

from .widgets.asset_library_panel import AssetLibraryPanel
from .widgets.plan_editor_panel import PlanEditorPanel
from .widgets.plan_tree import PlanTreeWidget, plan_summary
from .workers.plan_run_worker import PlanRunWorker, RunOptions


class MainWindow(QMainWindow):
    def __init__(
        self,
        initial_plan_path: Path | None = None,
        config_path: Path | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("企微素材转发助手")
        self.resize(1180, 780)

        self._config_path = config_path
        self._plan: BatchPlan | None = None
        self._plan_path: Path | None = None

        self._worker_thread: QThread | None = None
        self._worker: PlanRunWorker | None = None
        self._last_reports: list[str] = []
        self._account_service = self._build_account_service()
        self._current_account = ""

        self._build_ui()
        self._build_menu()
        self._init_account_context()

        if initial_plan_path is not None:
            self._load_plan_path(initial_plan_path)
        else:
            self._refresh_summary()
            self.statusBar().showMessage("就绪 · 请先打开任务文件")

    # ---------- UI ---------- #

    def _build_ui(self) -> None:
        central = QWidget()
        vbox = QVBoxLayout(central)
        vbox.setContentsMargins(8, 8, 8, 8)
        vbox.setSpacing(6)

        account_row = QHBoxLayout()
        account_row.addWidget(QLabel("当前企微账号:"))
        self._account_combo = QComboBox()
        self._btn_refresh_account = QPushButton("刷新账号")
        account_row.addWidget(self._account_combo)
        account_row.addWidget(self._btn_refresh_account)
        account_row.addStretch(1)
        vbox.addLayout(account_row)

        self._summary_label = QLabel("尚未加载任务方案")
        self._summary_label.setStyleSheet(
            "QLabel { padding:6px 10px; background:#f0f4f8;"
            " border:1px solid #d0d7de; border-radius:4px;"
            " font-size:12pt; }"
        )
        self._summary_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        vbox.addWidget(self._summary_label)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._side = QListWidget()
        self._side.setMinimumWidth(160)
        self._side.setMaximumWidth(220)
        self._side.addItem(QListWidgetItem("素材接收"))
        self._side.addItem(QListWidgetItem("待发送清单"))
        self._side.addItem(QListWidgetItem("发送记录"))
        self._side.addItem(QListWidgetItem("发送对象"))
        self._side.addItem(QListWidgetItem("系统设置"))
        splitter.addWidget(self._side)

        self._tabs = QTabWidget()
        self._tabs.setTabPosition(QTabWidget.TabPosition.North)
        self._tabs.setDocumentMode(True)

        self._plan_tree = PlanTreeWidget()
        tab_plan = QWidget()
        tab_plan_layout = QVBoxLayout(tab_plan)
        tab_plan_layout.setContentsMargins(0, 0, 0, 0)
        tab_plan_layout.addWidget(self._plan_tree)
        self._tabs.addTab(tab_plan, "素材接收")

        self._edit_tab = self._build_edit_tab()
        self._tabs.addTab(self._edit_tab, "待发送清单")

        self._run_tab = self._build_run_tab()
        self._tabs.addTab(self._run_tab, "发送记录")
        self._asset_tab = self._build_asset_tab()
        self._tabs.addTab(self._asset_tab, "发送对象")
        self._settings_tab = self._build_settings_tab()
        self._tabs.addTab(self._settings_tab, "系统设置")
        self._account_combo.currentIndexChanged.connect(self._on_account_changed)
        self._btn_refresh_account.clicked.connect(self._init_account_context)
        self._side.currentRowChanged.connect(self._on_side_changed)
        self._side.setCurrentRow(0)

        splitter.addWidget(self._tabs)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([180, 980])

        vbox.addWidget(splitter, 1)
        self.setCentralWidget(central)

        self.statusBar().showMessage("就绪")

    def _build_run_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        opts = QWidget()
        grid = QGridLayout(opts)
        grid.setContentsMargins(6, 6, 6, 6)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        self._dry_run_cb = QCheckBox("演练一次（不真实发送）")
        self._dry_run_cb.setChecked(True)
        self._loose_cb = QCheckBox("失败后继续后续条目")
        self._resume_cb = QCheckBox("从上次进度继续")
        self._ignore_schedule_cb = QCheckBox("忽略时段和配额限制")
        self._no_jitter_cb = QCheckBox("使用固定发送间隔")
        self._keep_remote_cb = QCheckBox("保留设备临时文件")

        self._limit_spin = QSpinBox()
        self._limit_spin.setMinimum(0)
        self._limit_spin.setMaximum(9999)
        self._limit_spin.setValue(0)
        self._limit_spin.setToolTip("0 表示全部联系人")

        self._report_dir_edit = QLineEdit("runtime/reports")

        grid.addWidget(self._dry_run_cb, 0, 0)
        grid.addWidget(self._loose_cb, 0, 1)
        grid.addWidget(self._resume_cb, 0, 2)

        grid.addWidget(self._ignore_schedule_cb, 1, 0)
        grid.addWidget(self._no_jitter_cb, 1, 1)
        grid.addWidget(self._keep_remote_cb, 1, 2)

        grid.addWidget(QLabel("每批最多发送人数:"), 2, 0)
        grid.addWidget(self._limit_spin, 2, 1)
        grid.addWidget(QLabel("记录保存目录:"), 3, 0)
        grid.addWidget(self._report_dir_edit, 3, 1, 1, 2)

        root.addWidget(opts)

        btns = QHBoxLayout()
        self._btn_start = QPushButton("开始执行")
        self._btn_stop = QPushButton("停止")
        self._btn_open_reports = QPushButton("打开报告目录")
        self._btn_open_latest_report = QPushButton("打开最新报告")
        self._btn_clear_log = QPushButton("清空日志")
        self._btn_export_log = QPushButton("导出日志…")
        self._auto_scroll_cb = QCheckBox("自动滚到底")
        self._auto_scroll_cb.setChecked(True)

        self._btn_stop.setEnabled(False)
        self._btn_open_reports.setEnabled(False)
        self._btn_open_latest_report.setEnabled(False)

        self._btn_start.clicked.connect(self._on_start_run)
        self._btn_stop.clicked.connect(self._on_stop_run)
        self._btn_open_reports.clicked.connect(self._on_open_report_dir)
        self._btn_open_latest_report.clicked.connect(self._on_open_latest_report)
        self._btn_clear_log.clicked.connect(self._on_clear_run_log)
        self._btn_export_log.clicked.connect(self._on_export_run_log)

        btns.addWidget(self._btn_start)
        btns.addWidget(self._btn_stop)
        btns.addWidget(self._btn_open_reports)
        btns.addWidget(self._btn_open_latest_report)
        btns.addWidget(self._btn_clear_log)
        btns.addWidget(self._btn_export_log)
        btns.addWidget(self._auto_scroll_cb)
        btns.addStretch(1)
        root.addLayout(btns)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._run_status_label = QLabel("未开始")

        root.addWidget(self._progress)
        root.addWidget(self._run_status_label)

        self._run_log = QTextEdit()
        self._run_log.setReadOnly(True)
        # 用系统等宽字体, 让 tag/时间戳/dict 输出对齐更好读
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        if mono.family():
            f = QFont(mono)
            f.setPointSize(max(9, mono.pointSize()))
            self._run_log.setFont(f)
        root.addWidget(self._run_log, 1)

        self._dry_run_cb.toggled.connect(self._on_dry_run_toggled)
        self._on_dry_run_toggled(self._dry_run_cb.isChecked())

        return w

    def _build_menu(self) -> None:
        mb = self.menuBar()

        m_file = mb.addMenu("文件(&F)")

        act_open = QAction("打开任务文件…", self)
        act_open.setShortcut(QKeySequence.StandardKey.Open)
        act_open.triggered.connect(self._on_open_plan)
        m_file.addAction(act_open)

        act_reload = QAction("重新加载", self)
        act_reload.setShortcut("F5")
        act_reload.triggered.connect(self._on_reload)
        m_file.addAction(act_reload)

        m_file.addSeparator()
        act_quit = QAction("退出", self)
        act_quit.setShortcut(QKeySequence.StandardKey.Quit)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_quit)

        m_help = mb.addMenu("帮助(&H)")
        act_about = QAction("关于", self)
        act_about.triggered.connect(self._on_about)
        m_help.addAction(act_about)

    def _build_edit_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        self._plan_editor = PlanEditorPanel(plan=self._plan)
        self._plan_editor.plan_applied.connect(self._on_plan_applied)
        self._plan_editor.plan_saved.connect(self._on_plan_saved)
        self._plan_editor.status.connect(self._on_plan_editor_status)
        self._plan_editor.error.connect(self._on_plan_editor_error)
        layout.addWidget(self._plan_editor)
        return w

    def _build_asset_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        self._asset_panel = AssetLibraryPanel()
        self._asset_panel.status.connect(self._on_asset_status)
        self._asset_panel.error.connect(self._on_asset_error)
        self._asset_panel.library_changed.connect(self._on_library_changed)
        layout.addWidget(self._asset_panel)
        return w

    def _build_settings_tab(self) -> QWidget:
        from .widgets.settings_panel import SettingsPanel
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        self._settings_panel = SettingsPanel(config_path=self._config_path)
        self._settings_panel.config_saved.connect(self._on_config_saved)
        self._settings_panel.status.connect(
            lambda m: self.statusBar().showMessage(m, 5000)
        )
        self._settings_panel.error.connect(
            lambda m: self.statusBar().showMessage(f"配置错误: {m}", 5000)
        )
        layout.addWidget(self._settings_panel)
        return w

    # ---------- 交互 ---------- #

    def _on_side_changed(self, row: int) -> None:
        # 侧栏 index 与 tab index 一一对应
        if 0 <= row < self._tabs.count():
            self._tabs.setCurrentIndex(row)
        else:
            self._tabs.setCurrentIndex(0)

    def _on_config_saved(self, path: str) -> None:
        """SettingsPanel 保存后, 给用户一个"已生效对哪些流程"的提示。"""
        self.statusBar().showMessage(
            f"配置已保存: {path}（下次「开始执行」会重新读盘生效）", 8000
        )
        self._append_run_log(f"[settings] 已保存 {path}，下次执行会重新读盘")
        self._init_account_context()

    def _on_dry_run_toggled(self, checked: bool) -> None:
        # dry-run 时 ignore-schedule 与 keep-remote 无意义
        self._ignore_schedule_cb.setEnabled(not checked)
        self._keep_remote_cb.setEnabled(not checked)

    def _on_open_plan(self) -> None:
        start_dir = str(self._plan_path.parent if self._plan_path else Path("samples"))
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "选择任务文件",
            start_dir,
            "任务文件 (*.json);;所有文件 (*.*)",
        )
        if not path_str:
            return
        self._load_plan_path(Path(path_str))

    def _on_reload(self) -> None:
        if self._plan_path is None:
            self.statusBar().showMessage("还没有任务文件，暂时无法重新加载", 3000)
            return
        self._load_plan_path(self._plan_path)

    def _on_about(self) -> None:
        QMessageBox.information(
            self,
            "关于",
            "企微素材转发助手\n用于素材编码、对象选择、发送记录与系统设置。",
        )

    def _on_start_run(self) -> None:
        if self._plan is None:
            QMessageBox.warning(self, "暂时无法开始", self._guide("请先打开任务文件后再开始发送。"))
            return
        if self._worker_thread is not None:
            QMessageBox.information(self, "任务进行中", "当前已有发送任务在执行，请先停止或等待完成。")
            return

        self._tabs.setCurrentIndex(1)
        self._run_log.clear()
        self._last_reports = []
        self._btn_open_reports.setEnabled(False)
        self._btn_open_latest_report.setEnabled(False)

        plan_copy = BatchPlan.model_validate(self._plan.model_dump(mode="json"))
        opts = RunOptions(
            dry_run=self._dry_run_cb.isChecked(),
            loose=self._loose_cb.isChecked(),
            resume=self._resume_cb.isChecked(),
            ignore_schedule=self._ignore_schedule_cb.isChecked(),
            no_jitter=self._no_jitter_cb.isChecked(),
            keep_remote=self._keep_remote_cb.isChecked(),
            limit_contacts=int(self._limit_spin.value()),
            report_dir=self._report_dir_edit.text().strip() or "runtime/reports",
        )

        self._worker_thread = QThread(self)
        self._worker = PlanRunWorker(plan_copy, opts, config_path=self._config_path)
        self._worker.moveToThread(self._worker_thread)

        self._worker_thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_worker_progress)
        self._worker.log.connect(self._append_run_log)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.failed.connect(self._on_worker_failed)

        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.failed.connect(self._worker_thread.quit)
        self._worker_thread.finished.connect(self._on_worker_thread_finished)

        self._set_running_ui(True)
        self._progress.setValue(0)
        self._run_status_label.setText("启动中…")
        self.statusBar().showMessage("执行中…")
        self._append_run_log("=== 开始执行 ===")

        self._worker_thread.start()

    def _on_stop_run(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._append_run_log("已请求停止。")

    def _on_open_report_dir(self) -> None:
        target: str
        if self._last_reports:
            target = str(Path(self._last_reports[0]).parent)
        else:
            target = self._report_dir_edit.text().strip() or "runtime/reports"
        self._reveal_path(Path(target))

    def _on_open_latest_report(self) -> None:
        """优先打开运行返回的记录，否则打开目录中最新记录。"""
        target: Path | None = None
        if self._last_reports:
            target = Path(self._last_reports[0])
        else:
            report_dir = Path(self._report_dir_edit.text().strip() or "runtime/reports")
            if report_dir.is_dir():
                candidates = sorted(
                    (p for p in report_dir.iterdir() if p.is_file()),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if candidates:
                    target = candidates[0]

        if target is None or not target.exists():
            QMessageBox.information(self, "暂无记录", self._guide("还没有发送记录。请先执行一次任务后再查看。"))
            return
        self._reveal_path(target)

    @staticmethod
    def _reveal_path(p: Path) -> None:
        """跨平台打开目录或文件。"""
        try:
            os.startfile(str(p.resolve()))  # type: ignore[attr-defined]
        except Exception as e:
            QMessageBox.warning(None, "打开失败", f"{e}\n\n你可以这样做：\n1) 检查路径是否存在\n2) 检查是否有访问权限")

    def _on_clear_run_log(self) -> None:
        self._run_log.clear()

    def _on_export_run_log(self) -> None:
        text = self._run_log.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "暂无日志", "当前还没有可导出的日志。")
            return
        default = str(Path("runtime") / "run_log.txt")
        path_str, _ = QFileDialog.getSaveFileName(
            self,
            "导出执行日志",
            default,
            "文本文件 (*.txt);;所有文件 (*.*)",
        )
        if not path_str:
            return
        out = Path(path_str)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        self.statusBar().showMessage(f"日志已导出: {out}", 5000)

    # ---------- Worker 回调 ---------- #

    def _on_worker_progress(self, idx: int, total: int, status: str, brief: str) -> None:
        if total > 0:
            self._progress.setValue(int((idx / total) * 100))
        self._run_status_label.setText(f"{idx}/{total} · {status} · {brief}")

    def _on_worker_finished(self, summary: dict) -> None:
        counts = summary.get("counts", {})
        reports = summary.get("reports", [])
        stopped = bool(summary.get("stopped", False))

        self._last_reports = list(reports)
        self._btn_open_reports.setEnabled(bool(reports))
        self._btn_open_latest_report.setEnabled(bool(reports))

        parts = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        prefix = "已停止" if stopped else "已完成"
        self._append_run_log(f"=== {prefix}: {parts} ===")
        for p in reports:
            self._append_run_log(f"报告: {p}")

        self._run_status_label.setText(f"{prefix} · {parts}" if parts else prefix)
        self.statusBar().showMessage(prefix, 5000)

    def _on_worker_failed(self, err: str) -> None:
        self._append_run_log(f"=== 发送失败: {err} ===")
        self._run_status_label.setText("执行失败")
        self.statusBar().showMessage("执行失败", 5000)
        QMessageBox.critical(self, "执行失败", self._guide(f"{err}\n请检查企微是否登录、网络是否可用。"))

    def _on_worker_thread_finished(self) -> None:
        self._set_running_ui(False)

        if self._worker is not None:
            self._worker.deleteLater()
        if self._worker_thread is not None:
            self._worker_thread.deleteLater()

        self._worker = None
        self._worker_thread = None

    def _on_asset_status(self, msg: str) -> None:
        self.statusBar().showMessage(msg, 5000)
        self._append_run_log(f"[asset] {msg}")

    def _on_asset_error(self, msg: str) -> None:
        self.statusBar().showMessage(f"素材库错误: {msg}", 5000)
        self._append_run_log(f"[asset-error] {msg}")

    def _on_library_changed(self) -> None:
        """素材库有变动时, 让 PlanEditor 的 tag 下拉自动刷新, 无需用户手点。"""
        try:
            self._plan_editor.reload_asset_tags()
        except Exception as e:  # 编辑器还没建好或异常, 不影响素材库自身
            logger.debug(f"library_changed → reload tags 失败(忽略): {e}")

    def _on_plan_editor_status(self, msg: str) -> None:
        self.statusBar().showMessage(msg, 5000)

    def _on_plan_editor_error(self, msg: str) -> None:
        self.statusBar().showMessage(f"编辑器错误: {msg}", 5000)

    def _on_plan_applied(self, plan: BatchPlan) -> None:
        self.set_plan(plan, self._plan_path)
        self.statusBar().showMessage("任务方案已应用并刷新", 5000)

    def _on_plan_saved(self, path: str) -> None:
        self._plan_path = Path(path)
        self.statusBar().showMessage(f"任务方案已保存: {path}", 5000)

    def _append_run_log(self, text: str) -> None:
        self._run_log.append(text)
        # F: 若勾选"自动滚到底"则每次追加后把光标推到末尾
        if getattr(self, "_auto_scroll_cb", None) is None or self._auto_scroll_cb.isChecked():
            cur = self._run_log.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            self._run_log.setTextCursor(cur)
            sb = self._run_log.verticalScrollBar()
            if sb is not None:
                sb.setValue(sb.maximum())

    def _set_running_ui(self, running: bool) -> None:
        self._btn_start.setEnabled((self._plan is not None) and (not running))
        self._btn_stop.setEnabled(running)

    # ---------- Plan 加载 ---------- #

    def _load_plan_path(self, path: Path) -> None:
        try:
            plan = load_plan(path)
        except Exception as e:
            logger.exception(f"加载 plan 失败: {path}")
            QMessageBox.critical(
                self,
                "加载失败",
                self._guide(f"无法读取任务文件：{path.name}\n{type(e).__name__}: {e}\n请确认文件内容是有效 JSON。"),
            )
            self.statusBar().showMessage(f"加载失败: {path.name}", 5000)
            return

        self.set_plan(plan, path)

    def set_plan(self, plan: BatchPlan | None, path: Path | None = None) -> None:
        self._plan = plan
        self._plan_path = path
        self._plan_tree.populate(plan)
        self._refresh_summary()
        if plan is not None:
            self._plan_editor.set_plan(plan)

        if plan is None:
            self.setWindowTitle("企微素材转发助手")
            self.statusBar().showMessage("已清空", 3000)
        else:
            name = path.name if path else "(内存)"
            self.setWindowTitle(f"企微素材转发助手 · {name}")
            self.statusBar().showMessage(f"已加载: {name}", 5000)
            logger.info(f"GUI 加载 plan: {path} · tasks={len(plan.tasks)}")

        self._set_running_ui(False)

    def _refresh_summary(self) -> None:
        self._summary_label.setText(plan_summary(self._plan))

    @staticmethod
    def _guide(message: str) -> str:
        return f"{message}\n\n你可以这样做：\n1) 先检查输入是否完整\n2) 再点击“刷新”重试\n3) 仍失败请查看执行日志"

    def _build_account_service(self) -> AccountMapService:
        try:
            cfg = load_config(self._config_path) if self._config_path else load_config()
            return AccountMapService(
                wxwork_root=cfg.pc_wecom.wxwork_root,
                path=cfg.pc_wecom.account_map_file,
            )
        except Exception:
            return AccountMapService()

    def _init_account_context(self) -> None:
        current = ""
        try:
            current = self._account_service.detect_active_account()
        except Exception:
            current = ""

        accounts = self._account_service.list_accounts()
        if current and current not in accounts:
            accounts.append(current)
            accounts.sort()

        self._account_combo.blockSignals(True)
        self._account_combo.clear()
        for acct in accounts:
            alias = self._account_service.get(acct)
            label = f"{acct}（{alias.wecom_alias or alias.wx_alias}）" if alias else acct
            self._account_combo.addItem(label, userData=acct)
        self._account_combo.blockSignals(False)

        if accounts:
            idx = 0
            for i in range(self._account_combo.count()):
                if self._account_combo.itemData(i) == current:
                    idx = i
                    break
            self._account_combo.setCurrentIndex(idx)
            self._on_account_changed(idx)
        else:
            self.statusBar().showMessage("未检测到企微账号目录", 5000)

    def _on_account_changed(self, index: int) -> None:
        acct = self._account_combo.itemData(index) if index >= 0 else None
        if not acct:
            return
        self._current_account = str(acct)
        base = project_root() / "runtime" / "accounts" / self._current_account
        base.mkdir(parents=True, exist_ok=True)
        asset_path = base / "asset_library.json"
        self._asset_panel.set_library_path(asset_path)
        # PlanEditor 读取 tag 时依赖 _library_path，这里同步切换账号库。
        self._plan_editor._library_path = asset_path
        self._plan_editor.reload_asset_tags()
        self._report_dir_edit.setText(str(base / "reports"))
        self.statusBar().showMessage(f"已切换账号: {self._current_account}", 5000)

    # ---------- 对测试暴露的只读访问 ---------- #

    @property
    def plan(self) -> BatchPlan | None:
        return self._plan

    @property
    def plan_tree(self) -> PlanTreeWidget:
        return self._plan_tree

    @property
    def asset_panel(self) -> AssetLibraryPanel:
        return self._asset_panel

    @property
    def plan_editor(self) -> PlanEditorPanel:
        return self._plan_editor

    @property
    def settings_panel(self):
        return self._settings_panel
