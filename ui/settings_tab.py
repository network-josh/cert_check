# ui/settings_tab.py

from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QCheckBox
)

from .types import LogEmitterType


class SettingsTab(QWidget):
    """
    UI for application-level settings (theme, timezone, logging options).
    """

    def __init__(self, app_config: dict, commit_callback, log_emitter: LogEmitterType):
        """
        app_config: dict loaded via load_app_config()
        commit_callback: function to call when config changes
        log_emitter: to log messages
        """
        super().__init__()
        self.app_config = app_config
        self.commit_callback = commit_callback
        self.log_emitter = log_emitter

        layout = QVBoxLayout()
        self.setLayout(layout)

        # --- Theme Selection ---
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Theme:"))
        self.combo_theme = QComboBox()
        self.combo_theme.addItems(["light", "dark"])
        self.combo_theme.setCurrentText(self.app_config.get("theme", "light"))
        theme_row.addWidget(self.combo_theme)
        theme_row.addStretch(1)

        layout.addLayout(theme_row)

        # --- Timestamp Toggle ---
        self.chk_timestamps = QCheckBox("Show timestamps in console")
        self.chk_timestamps.setChecked(self.app_config.get("console_timestamps", False))
        layout.addWidget(self.chk_timestamps)

        # --- Timezone Mode (system only for now) ---
        layout.addWidget(QLabel("Timezone: System time only (region selection coming later)"))

        # --- Save Button ---
        self.btn_save = QPushButton("Save Settings")
        layout.addWidget(self.btn_save)

        self.btn_save.clicked.connect(self.commit_changes)

        layout.addStretch(1)

    def commit_changes(self):
        """
        Called when clicking Save Settings.
        Writes config to disk via callback in MainWindow.
        """
        self.app_config["theme"] = self.combo_theme.currentText()
        self.app_config["console_timestamps"] = self.chk_timestamps.isChecked()

        # Future expansion:
        # self.app_config["timezone_mode"] = ...
        # self.app_config["timezone_region"] = ...

        self.commit_callback(self.app_config)
        self.log_emitter.message.emit("Settings saved.", "SETTINGS")
