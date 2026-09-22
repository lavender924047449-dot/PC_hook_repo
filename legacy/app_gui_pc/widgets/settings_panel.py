"""
系统设置面板（面向运营）。

覆盖 (常用运行时开关):
    device.adb_port / connect_timeout / wecom_package
    schedule.min_interval_s / max_interval_s / hourly_limit / daily_limit /
             working_hours[start, end]
    timing.pre_roll_ms / post_roll_ms / after_send_wait_s
    audio.sample_rate / loudnorm_i
    logging.level / keep_days

不覆盖 (改的机会低, 出错风险高):
    locators.*  → 企微 UI 升级时才动, 直接编 YAML
    ffmpeg.bundled_path / logging.dir / audio 其余细节 → 同上

行为:
    - 打开时读 config.yaml (走 pydantic 校验), 表单填当前值
    - "保存" → 校验合法后, dump 回 config.yaml (会覆写注释, 顶部会加一行说明)
    - "重新加载" → 重读磁盘, 丢弃未保存的编辑
    - 保存成功后发 `config_saved` 信号, 让 MainWindow 提示用户"重启生效"
"""

from __future__ import annotations

from pathlib import Path

import yaml
from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.config import AppConfig, load_config, project_root


SAVE_HEADER = (
    "# wecom-voice-blaster 主配置\n"
    "# 本文件可能被 GUI · 设置面板 覆写; 已有的注释在覆写后会消失.\n"
    "# 高级字段 (locators/ffmpeg 等) 仍需手动编辑.\n"
)


class SettingsPanel(QWidget):
    #: 保存成功时发出, 参数是被写入的配置文件绝对路径
    config_saved = Signal(str)
    status = Signal(str)
    error = Signal(str)

    def __init__(self, config_path: Path | None = None, parent=None) -> None:
        super().__init__(parent)
        self._config_path = Path(config_path) if config_path else (
            project_root() / "config.yaml"
        )
        self._build_ui()
        self.reload_from_disk()

    # ---------- 外部 API ---------- #

    @property
    def config_path(self) -> Path:
        return self._config_path

    def reload_from_disk(self) -> None:
        """从磁盘重读 config.yaml, 丢弃当前表单未保存的编辑."""
        try:
            cfg = load_config(self._config_path)
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "加载失败", self._guide(str(e)))
            return
        self._apply_to_form(cfg)
        self.status.emit(f"已加载: {self._config_path}")

    def to_app_config(self) -> AppConfig:
        """把表单当前值组装成 AppConfig; 校验失败会抛 pydantic.ValidationError."""
        raw = self._raw_yaml_dict()
        # 表单只覆盖它管辖的字段, 未覆盖字段 (locators 等) 保持磁盘值
        payload = self._merge_form_into_raw(raw)
        return AppConfig.model_validate(payload)

    def save_to_disk(self) -> Path:
        """校验 + 写盘; 抛异常给上层处理."""
        raw = self._raw_yaml_dict()
        payload = self._merge_form_into_raw(raw)
        AppConfig.model_validate(payload)   # 校验
        text = SAVE_HEADER + yaml.safe_dump(
            payload, allow_unicode=True, sort_keys=False, default_flow_style=False,
        )
        self._config_path.write_text(text, encoding="utf-8")
        return self._config_path

    # ---------- 内部: UI 构造 ---------- #

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(8)

        top = QHBoxLayout()
        top.addWidget(QLabel("配置文件:"))
        self._path_label = QLabel(str(self._config_path))
        self._path_label.setStyleSheet("QLabel { color:#555; }")
        top.addWidget(self._path_label, 1)
        self._btn_reload = QPushButton("重新加载")
        self._btn_save = QPushButton("保存")
        top.addWidget(self._btn_reload)
        top.addWidget(self._btn_save)
        root.addLayout(top)

        # ---- device ---- #
        gb_dev = QGroupBox("设备连接（兼容模式）")
        f_dev = QFormLayout(gb_dev)
        self._sp_adb_port = QSpinBox()
        self._sp_adb_port.setRange(1, 65535)
        self._sp_conn_to = QDoubleSpinBox()
        self._sp_conn_to.setRange(0.5, 60.0)
        self._sp_conn_to.setDecimals(1)
        self._sp_conn_to.setSingleStep(0.5)
        self._le_wecom_pkg = QLineEdit()
        f_dev.addRow("adb_port", self._sp_adb_port)
        f_dev.addRow("连接超时(秒)", self._sp_conn_to)
        f_dev.addRow("wecom_package", self._le_wecom_pkg)
        root.addWidget(gb_dev)

        # ---- schedule ---- #
        gb_sch = QGroupBox("发送节流")
        g_sch = QGridLayout(gb_sch)
        self._sp_min_int = QDoubleSpinBox(); self._sp_min_int.setRange(0.0, 600.0); self._sp_min_int.setDecimals(1)
        self._sp_max_int = QDoubleSpinBox(); self._sp_max_int.setRange(0.0, 3600.0); self._sp_max_int.setDecimals(1)
        self._sp_hour_lim = QSpinBox(); self._sp_hour_lim.setRange(1, 100_000)
        self._sp_day_lim = QSpinBox(); self._sp_day_lim.setRange(1, 1_000_000)
        self._sp_wh_start = QSpinBox(); self._sp_wh_start.setRange(0, 23)
        self._sp_wh_end = QSpinBox(); self._sp_wh_end.setRange(1, 24)
        g_sch.addWidget(QLabel("min_interval_s"), 0, 0); g_sch.addWidget(self._sp_min_int, 0, 1)
        g_sch.addWidget(QLabel("max_interval_s"), 0, 2); g_sch.addWidget(self._sp_max_int, 0, 3)
        g_sch.addWidget(QLabel("hourly_limit"),   1, 0); g_sch.addWidget(self._sp_hour_lim, 1, 1)
        g_sch.addWidget(QLabel("daily_limit"),    1, 2); g_sch.addWidget(self._sp_day_lim, 1, 3)
        g_sch.addWidget(QLabel("发送时段"), 2, 0)
        wh_row = QHBoxLayout()
        wh_row.addWidget(self._sp_wh_start)
        wh_row.addWidget(QLabel("→"))
        wh_row.addWidget(self._sp_wh_end)
        wh_row.addStretch(1)
        wh_wrap = QWidget(); wh_wrap.setLayout(wh_row)
        g_sch.addWidget(wh_wrap, 2, 1, 1, 3)
        root.addWidget(gb_sch)

        # ---- timing ---- #
        gb_t = QGroupBox("发送时序")
        f_t = QFormLayout(gb_t)
        self._sp_pre_roll = QSpinBox(); self._sp_pre_roll.setRange(0, 10_000)
        self._sp_post_roll = QSpinBox(); self._sp_post_roll.setRange(0, 10_000)
        self._sp_after_wait = QDoubleSpinBox(); self._sp_after_wait.setRange(0.0, 60.0); self._sp_after_wait.setDecimals(2)
        f_t.addRow("pre_roll_ms",       self._sp_pre_roll)
        f_t.addRow("post_roll_ms",      self._sp_post_roll)
        f_t.addRow("发送后等待(秒)", self._sp_after_wait)
        root.addWidget(gb_t)

        # ---- audio ---- #
        gb_a = QGroupBox("音频常用参数")
        f_a = QFormLayout(gb_a)
        self._sp_sr = QSpinBox(); self._sp_sr.setRange(8000, 192000); self._sp_sr.setSingleStep(1000)
        self._sp_loud_i = QDoubleSpinBox(); self._sp_loud_i.setRange(-70.0, 0.0); self._sp_loud_i.setDecimals(1)
        f_a.addRow("采样率 (Hz)", self._sp_sr)
        f_a.addRow("标准响度 (LUFS)", self._sp_loud_i)
        root.addWidget(gb_a)

        # ---- logging ---- #
        gb_l = QGroupBox("日志")
        f_l = QFormLayout(gb_l)
        self._cb_level = QComboBox()
        self._cb_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self._sp_keep = QSpinBox(); self._sp_keep.setRange(1, 365)
        f_l.addRow("level",      self._cb_level)
        f_l.addRow("keep_days",  self._sp_keep)
        root.addWidget(gb_l)

        root.addStretch(1)

        self._status_label = QLabel("就绪")
        self._status_label.setStyleSheet("QLabel { color:#555; }")
        root.addWidget(self._status_label)

        # signals
        self._btn_reload.clicked.connect(self._on_reload_clicked)
        self._btn_save.clicked.connect(self._on_save_clicked)

    # ---------- 内部: 表单 ↔ AppConfig ---------- #

    def _apply_to_form(self, cfg: AppConfig) -> None:
        self._sp_adb_port.setValue(cfg.device.adb_port)
        self._sp_conn_to.setValue(cfg.device.connect_timeout)
        self._le_wecom_pkg.setText(cfg.device.wecom_package)

        self._sp_min_int.setValue(float(cfg.schedule.min_interval_s))
        self._sp_max_int.setValue(float(cfg.schedule.max_interval_s))
        self._sp_hour_lim.setValue(cfg.schedule.hourly_limit)
        self._sp_day_lim.setValue(cfg.schedule.daily_limit)
        self._sp_wh_start.setValue(cfg.schedule.working_hours[0])
        self._sp_wh_end.setValue(cfg.schedule.working_hours[1])

        self._sp_pre_roll.setValue(cfg.timing.pre_roll_ms)
        self._sp_post_roll.setValue(cfg.timing.post_roll_ms)
        self._sp_after_wait.setValue(cfg.timing.after_send_wait_s)

        self._sp_sr.setValue(cfg.audio.sample_rate)
        self._sp_loud_i.setValue(cfg.audio.loudnorm_i)

        idx = self._cb_level.findText(cfg.logging.level.upper())
        self._cb_level.setCurrentIndex(max(0, idx))
        self._sp_keep.setValue(cfg.logging.keep_days)

    def _raw_yaml_dict(self) -> dict:
        """从磁盘读原始 dict; locators 等未覆盖字段将被保留."""
        if not self._config_path.exists():
            return {}
        return yaml.safe_load(self._config_path.read_text(encoding="utf-8")) or {}

    def _merge_form_into_raw(self, raw: dict) -> dict:
        """把当前表单值合并进 raw dict, 只覆盖 SettingsPanel 管辖的字段."""
        raw = dict(raw)  # shallow copy

        dev = dict(raw.get("device") or {})
        dev["adb_port"] = int(self._sp_adb_port.value())
        dev["connect_timeout"] = float(self._sp_conn_to.value())
        dev["wecom_package"] = self._le_wecom_pkg.text().strip() or "com.tencent.wework"
        raw["device"] = dev

        sch = dict(raw.get("schedule") or {})
        sch["min_interval_s"] = float(self._sp_min_int.value())
        sch["max_interval_s"] = float(self._sp_max_int.value())
        sch["hourly_limit"] = int(self._sp_hour_lim.value())
        sch["daily_limit"] = int(self._sp_day_lim.value())
        sch["working_hours"] = [int(self._sp_wh_start.value()), int(self._sp_wh_end.value())]
        raw["schedule"] = sch

        t = dict(raw.get("timing") or {})
        t["pre_roll_ms"] = int(self._sp_pre_roll.value())
        t["post_roll_ms"] = int(self._sp_post_roll.value())
        t["after_send_wait_s"] = float(self._sp_after_wait.value())
        raw["timing"] = t

        a = dict(raw.get("audio") or {})
        a["sample_rate"] = int(self._sp_sr.value())
        a["loudnorm_i"] = float(self._sp_loud_i.value())
        raw["audio"] = a

        lg = dict(raw.get("logging") or {})
        lg["level"] = self._cb_level.currentText()
        lg["keep_days"] = int(self._sp_keep.value())
        raw["logging"] = lg

        return raw

    # ---------- 内部: 事件 ---------- #

    def _on_reload_clicked(self) -> None:
        self.reload_from_disk()
        self._status_label.setText("已重新加载")

    def _on_save_clicked(self) -> None:
        # 简单越界校验: max >= min, working_hours end > start
        if self._sp_max_int.value() < self._sp_min_int.value():
            QMessageBox.warning(
                self, "参数不合法",
                "最大间隔必须大于或等于最小间隔。",
            )
            return
        if self._sp_wh_end.value() <= self._sp_wh_start.value():
            QMessageBox.warning(
                self, "参数不合法",
                "发送时段的结束时刻必须大于开始时刻。",
            )
            return
        try:
            path = self.save_to_disk()
        except Exception as e:
            self.error.emit(str(e))
            QMessageBox.critical(self, "保存失败", self._guide(str(e)))
            return
        self._status_label.setText(f"已保存: {path}")
        self.status.emit(f"已保存: {path}")
        self.config_saved.emit(str(path))

    @staticmethod
    def _guide(msg: str) -> str:
        return f"{msg}\n\n你可以这样做：\n1) 检查当前输入值范围\n2) 点击“重新加载”恢复后再试\n3) 查看日志定位字段"
