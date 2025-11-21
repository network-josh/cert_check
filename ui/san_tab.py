# ui/san_tab.py

from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QFileDialog
)
from core.crypto_ops import load_pem_object
from core.san_ops import parse_user_sans, apply_default_dns_sans, format_ms_pki_san_string
from core.errors import CertToolError
from .types import LogEmitterType


class SanTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter

        layout = QVBoxLayout()
        self.setLayout(layout)

        row1 = QHBoxLayout()
        self.btn_load_csr = QPushButton("Load CSR")
        self.lbl_cn = QLabel("Common Name: (none)")
        row1.addWidget(self.btn_load_csr)
        row1.addWidget(self.lbl_cn)
        row1.addStretch(1)

        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Additional SANs (DNS/IP, sep by , or ;):"))
        self.edit_sans = QLineEdit()
        row2.addWidget(self.edit_sans)
        layout.addLayout(row2)

        self.btn_generate = QPushButton("Generate SAN String")
        layout.addWidget(self.btn_generate)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("MS PKI SAN String:"))
        self.edit_output = QLineEdit()
        layout.addLayout(row3)
        layout.addWidget(self.edit_output)

        self.btn_copy = QPushButton("Copy to Clipboard")
        layout.addWidget(self.btn_copy)

        self.btn_load_csr.clicked.connect(self.load_csr)
        self.btn_generate.clicked.connect(self.generate_san_string)
        self.btn_copy.clicked.connect(self.copy_to_clipboard)

        self.current_cn: str | None = None

    def load_csr(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select CSR", filter="CSR/PEM files (*.csr *.req *.pem *.txt);;All files (*.*)"
        )
        if not path:
            return

        try:
            obj, kind, _ = load_pem_object(path)
            if kind != "csr":
                raise CertToolError("Selected file is not a CSR.")
            csr = obj  # type: ignore
            cn = None
            for attr in csr.subject:
                if attr.oid == csr.subject.rfc4514_string.__self__.OID_COMMON_NAME:  # hacky, will fix later
                    cn = attr.value
                    break
        except Exception as e:
            self.log_emitter.message.emit(f"Failed to load CSR: {e}", "SAN")
            return

        if not cn:
            self.log_emitter.message.emit("No CN found in CSR.", "SAN")
            return

        self.current_cn = cn
        self.lbl_cn.setText(f"Common Name: {cn}")
        self.log_emitter.message.emit(f"Loaded CSR with CN={cn}", "SAN")

    def generate_san_string(self):
        if not self.current_cn:
            self.log_emitter.message.emit("Load a CSR first.", "SAN")
            return

        raw = self.edit_sans.text().strip()
        user_sans = parse_user_sans(raw)
        combined = apply_default_dns_sans(self.current_cn, user_sans, include_www=True)
        san_str = format_ms_pki_san_string(combined)
        self.edit_output.setText(san_str)
        self.log_emitter.message.emit(f"Generated SAN string: {san_str}", "SAN")

    def copy_to_clipboard(self):
        text = self.edit_output.text().strip()
        if not text:
            return
        self.window().clipboard().setText(text)
        self.log_emitter.message.emit("SAN string copied to clipboard.", "SAN")
