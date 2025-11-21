# ui/chain_tab.py

from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QFileDialog
)

from core.chain_ops import load_leaf_cert, find_chain_candidates
from core.errors import CertToolError
from .types import LogEmitterType


class ChainTab(QWidget):
    """
    UI helper to load a leaf certificate and scan a folder for matching chain certs.
    """

    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.btn_load_leaf = QPushButton("Load Leaf Certificate")
        self.btn_scan_chain = QPushButton("Scan Folder for Chain Certs")

        layout.addWidget(self.btn_load_leaf)
        layout.addWidget(self.btn_scan_chain)

        self.btn_load_leaf.clicked.connect(self.load_leaf)
        self.btn_scan_chain.clicked.connect(self.scan)

        self.leaf_cert = None

    def load_leaf(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Leaf Certificate")
        if not path:
            return

        try:
            cert = load_leaf_cert(path)
            self.leaf_cert = cert
            self.log_emitter.message.emit(f"Loaded leaf certificate: {path}", "CHAIN")
        except Exception as e:
            self.log_emitter.message.emit(f"Failed to load leaf cert: {e}", "CHAIN")

    def scan(self):
        if not self.leaf_cert:
            self.log_emitter.message.emit("Load a leaf cert first.", "CHAIN")
            return

        folder = QFileDialog.getExistingDirectory(self, "Select Folder of Chain Certificates")
        if not folder:
            return

        try:
            results = find_chain_candidates(self.leaf_cert, folder)
        except CertToolError as e:
            self.log_emitter.message.emit(f"Error scanning folder: {e}", "CHAIN")
            return

        if not results:
            self.log_emitter.message.emit("No chain candidates found.", "CHAIN")
            return

        self.log_emitter.message.emit("Chain candidates:", "CHAIN")
        for c in results:
            status = []
            if c.issuer_match: status.append("issuer-match")
            if c.aki_match:    status.append("aki-match")
            label = ", ".join(status) if status else "weak match"
            self.log_emitter.message.emit(
                f"  {c.path} → {label}",
                "CHAIN"
            )
