# ui/main_window.py

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget,
    QPlainTextEdit, QPushButton, QHBoxLayout, QDockWidget
)

from core.app_config import load_app_config, save_app_config

from ui.verify_tab import VerifyTab
from ui.san_tab import SanTab
from ui.csr_tab import CsrTab
from ui.chain_tab import ChainTab
from ui.settings_tab import SettingsTab


class LogEmitter(QObject):
    message = Signal(str, str)  # text, tag


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Certificate Tool (PySide6)")

        self.app_config = load_app_config()

        self.log_emitter = LogEmitter()
        self.log_emitter.message.connect(self._handle_log_message)

        # Tabs are the central widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.verify_tab   = VerifyTab(self.log_emitter)
        self.san_tab      = SanTab(self.log_emitter)
        self.csr_tab      = CsrTab(self.log_emitter)
        self.chain_tab    = ChainTab(self.log_emitter)
        self.settings_tab = SettingsTab(self.app_config, self.on_app_config_changed, self.log_emitter)

        self.tabs.addTab(self.verify_tab,   "Verify Set")
        self.tabs.addTab(self.san_tab,      "SAN Generator")
        self.tabs.addTab(self.csr_tab,      "Create CSR")
        self.tabs.addTab(self.chain_tab,    "Chain Helper")
        self.tabs.addTab(self.settings_tab, "Settings")

        # ── Console dock ──────────────────────────────────────────────────────
        console_frame = QWidget()
        console_layout = QVBoxLayout()
        console_layout.setContentsMargins(4, 4, 4, 4)
        console_frame.setLayout(console_layout)

        btn_row = QHBoxLayout()
        self.btn_clear_console = QPushButton("Clear Console")
        self.btn_new_log_file  = QPushButton("Start New Log File (not wired yet)")
        btn_row.addWidget(self.btn_clear_console)
        btn_row.addWidget(self.btn_new_log_file)
        btn_row.addStretch(1)
        console_layout.addLayout(btn_row)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        console_layout.addWidget(self.console)

        self.console_dock = QDockWidget("Console", self)
        self.console_dock.setWidget(console_frame)
        self.console_dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea)
        self.console_dock.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable  |
            QDockWidget.DockWidgetFeature.DockWidgetFloatable |
            QDockWidget.DockWidgetFeature.DockWidgetClosable
        )
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.console_dock)

        # ── Toolbar — always-visible Console toggle ───────────────────────────
        toolbar = self.addToolBar("View")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toggle = self.console_dock.toggleViewAction()
        toggle.setText("Console")
        toolbar.addAction(toggle)

        self.btn_clear_console.clicked.connect(self.console.clear)
        # self.btn_new_log_file.clicked.connect(self._start_new_log_file)  # TODO

        self.apply_theme(self.app_config.get("theme", "light"))

    # ── Logging ───────────────────────────────────────────────────────────────

    def _handle_log_message(self, text: str, tag: str) -> None:
        line = text
        if self.app_config.get("console_timestamps", False):
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{ts}][{tag}] {text}" if tag else f"[{ts}] {text}"
        else:
            if tag:
                line = f"[{tag}] {text}"

        if self.console.toPlainText():
            self.console.appendPlainText(line)
        else:
            self.console.setPlainText(line)

        # TODO: also write to daily log file via a core logger

    def on_app_config_changed(self, new_config: dict) -> None:
        self.app_config.update(new_config)
        save_app_config(self.app_config)
        self.apply_theme(self.app_config.get("theme", "light"))

    # ── Theme ─────────────────────────────────────────────────────────────────

    def apply_theme(self, theme: str) -> None:
        if theme == "dark":
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #2b2b2b;
                    color: #dddddd;
                }
                QWidget {
                    background-color: #2b2b2b;
                    color: #dddddd;
                }
                QPlainTextEdit, QTextEdit {
                    background-color: #1e1e1e;
                    color: #f0f0f0;
                }
                QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                    background-color: #3c3c3c;
                    color: #f0f0f0;
                }
                QPushButton {
                    background-color: #444444;
                    color: #ffffff;
                }
            """)
        else:
            self.setStyleSheet("")
