# ui/csr_tab.py

from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QFileDialog, QLineEdit
)

from core.csr_templates import list_templates, load_template
from .types import LogEmitterType


class CsrTab(QWidget):
    """
    UI for generating CSRs and keys, based on templates.
    """

    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter

        layout = QVBoxLayout()
        self.setLayout(layout)

        # Template Select
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Template:"))
        self.combo_templates = QComboBox()
        row1.addWidget(self.combo_templates)
        layout.addLayout(row1)

        # Template load button
        self.btn_load_template = QPushButton("Load Template")
        layout.addWidget(self.btn_load_template)

        # CSR CN Input
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Common Name:"))
        self.edit_cn = QLineEdit()
        row2.addWidget(self.edit_cn)
        layout.addLayout(row2)

        # Generate CSR Button
        self.btn_generate = QPushButton("Generate CSR + Key")
        layout.addWidget(self.btn_generate)

        self.btn_load_template.clicked.connect(self.load_selected_template)
        self.btn_generate.clicked.connect(self.generate_csr)

        self.refresh_templates()

    def refresh_templates(self):
        self.combo_templates.clear()
        self.combo_templates.addItems(list_templates())

    def load_selected_template(self):
        name = self.combo_templates.currentText().strip()
        if not name:
            self.log_emitter.message.emit("No template selected.", "CSR")
            return

        data = load_template(name)
        if not data:
            self.log_emitter.message.emit(f"Template '{name}' not found.", "CSR")
            return

        self.log_emitter.message.emit(
            f"Loaded template '{name}': {data}",
            "CSR"
        )

    def generate_csr(self):
        cn = self.edit_cn.text().strip()
        if not cn:
            self.log_emitter.message.emit("CN cannot be empty.", "CSR")
            return

        self.log_emitter.message.emit(
            f"(Stub) Would generate CSR for CN={cn}",
            "CSR"
        )
