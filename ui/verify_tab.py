# ui/verify_tab.py

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QGroupBox, QGridLayout,
)

from core.verify_set import verify_files, check_match, scan_folder, SlotResult
from core.csr_ops import is_key_encrypted
from core.errors import CertToolError
from .types import LogEmitterType

# (slot_key, display_label, file_filter, can_be_encrypted)
_SLOTS = [
    ("key",      "Private Key",     "Key files (*.key *.pem);;All files (*.*)",           True),
    ("cert",     "Certificate",     "Cert files (*.crt *.cer *.pem);;All files (*.*)",    False),
    ("csr",      "CSR",             "CSR files (*.csr *.req *.pem);;All files (*.*)",     False),
    ("old_cert", "Old Certificate", "Cert files (*.crt *.cer *.pem);;All files (*.*)",    False),
]


class VerifyTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter
        self._paths: Dict[str, str] = {}

        layout = QVBoxLayout()
        self.setLayout(layout)

        group = QGroupBox(
            "Files  —  Key and Certificate required; CSR and Old Certificate optional"
        )
        grid = QGridLayout()
        group.setLayout(grid)
        layout.addWidget(group)

        self._path_edits:  Dict[str, QLineEdit] = {}
        self._pw_edits:    Dict[str, QLineEdit] = {}
        self._pw_labels:   Dict[str, QLabel]    = {}
        self._hash_labels: Dict[str, QLabel]    = {}

        for row, (slot, label, filt, can_encrypt) in enumerate(_SLOTS):
            grid.addWidget(QLabel(f"{label}:"), row, 0)

            path_edit = QLineEdit()
            path_edit.setReadOnly(True)
            path_edit.setPlaceholderText("(none)")
            grid.addWidget(path_edit, row, 1)

            btn = QPushButton("Browse")
            btn.clicked.connect(
                lambda checked=False, s=slot, f=filt: self._browse(s, f)
            )
            grid.addWidget(btn, row, 2)

            # Password field — hidden by default, shown only when encryption detected
            pw_label = QLabel("Password:")
            pw_edit  = QLineEdit()
            pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
            pw_edit.setPlaceholderText("key password")
            pw_edit.setMaximumWidth(160)
            pw_label.setVisible(False)
            pw_edit.setVisible(False)
            grid.addWidget(pw_label, row, 3)
            grid.addWidget(pw_edit,  row, 4)

            hash_lbl = QLabel("")
            hash_lbl.setMinimumWidth(280)
            grid.addWidget(hash_lbl, row, 5)

            self._path_edits[slot]  = path_edit
            self._pw_labels[slot]   = pw_label
            self._pw_edits[slot]    = pw_edit
            self._hash_labels[slot] = hash_lbl

        btn_row = QHBoxLayout()
        self.btn_verify = QPushButton("Verify Selected Files")
        self.btn_scan   = QPushButton("Scan Folder")
        self.btn_clear  = QPushButton("Clear")
        btn_row.addWidget(self.btn_verify)
        btn_row.addWidget(self.btn_scan)
        btn_row.addWidget(self.btn_clear)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)
        layout.addStretch(1)

        self.btn_verify.clicked.connect(self._run_verify)
        self.btn_scan.clicked.connect(self._run_scan)
        self.btn_clear.clicked.connect(self._clear)

    # ------------------------------------------------------------------

    def _browse(self, slot: str, filt: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, f"Select {slot}", filter=filt)
        if not path:
            return

        self._paths[slot] = path
        self._path_edits[slot].setText(Path(path).name)
        self._hash_labels[slot].setText("")

        # Detect encryption and show/hide the password field
        encrypted = is_key_encrypted(path)
        self._pw_labels[slot].setVisible(encrypted)
        self._pw_edits[slot].setVisible(encrypted)
        if not encrypted:
            self._pw_edits[slot].clear()

    def _clear(self) -> None:
        self._paths.clear()
        for slot in self._path_edits:
            self._path_edits[slot].clear()
            self._hash_labels[slot].setText("")
            self._pw_edits[slot].clear()
            self._pw_labels[slot].setVisible(False)
            self._pw_edits[slot].setVisible(False)

    def _build_passwords(self) -> Dict[str, str]:
        return {
            slot: self._pw_edits[slot].text()
            for slot in self._pw_edits
            if self._pw_edits[slot].isVisible() and self._pw_edits[slot].text()
        }

    def _display_results(self, results: Dict[str, SlotResult]) -> None:
        for slot, (path, md5, encrypted) in results.items():
            enc_tag  = "  [encrypted]" if encrypted else ""
            hash_txt = f"MD5: {md5}" if md5 else "MD5: (unreadable — wrong/missing password?)" if encrypted else "MD5: (unreadable)"
            if slot in self._hash_labels:
                self._hash_labels[slot].setText(hash_txt)
            self.log_emitter.message.emit(
                f"  {slot}: {Path(path).name}{enc_tag}  —  {hash_txt}", "VERIFY"
            )

        match, common = check_match(results)
        loaded = sum(1 for _, md5, _ in results.values() if md5 is not None)
        if loaded < 2:
            self.log_emitter.message.emit(
                "Need at least 2 readable files to compare.", "VERIFY"
            )
        elif match:
            self.log_emitter.message.emit(f"MATCH  (modulus MD5: {common})", "VERIFY")
        else:
            self.log_emitter.message.emit(
                "MISMATCH — modulus hashes differ", "VERIFY"
            )

    def _run_verify(self) -> None:
        if not self._paths:
            self.log_emitter.message.emit(
                "No files selected. Use Browse or Scan Folder.", "VERIFY"
            )
            return
        self.log_emitter.message.emit("--- Verify ---", "VERIFY")
        try:
            results = verify_files(self._paths, passwords=self._build_passwords())
        except CertToolError as e:
            self.log_emitter.message.emit(f"Error: {e}", "VERIFY")
            return
        self._display_results(results)

    def _run_scan(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Select Folder with Certificate Files"
        )
        if not folder:
            return
        self._clear()
        self.log_emitter.message.emit(f"--- Scan: {folder} ---", "VERIFY")
        try:
            results = scan_folder(folder)
        except CertToolError as e:
            self.log_emitter.message.emit(f"Error: {e}", "VERIFY")
            return
        if not results:
            self.log_emitter.message.emit(
                "No certificate files found in folder.", "VERIFY"
            )
            return
        # Populate path fields and show password prompts for any encrypted keys
        for slot, (path, _, encrypted) in results.items():
            if slot in self._path_edits:
                self._paths[slot] = path
                self._path_edits[slot].setText(Path(path).name)
                self._pw_labels[slot].setVisible(encrypted)
                self._pw_edits[slot].setVisible(encrypted)
        self._display_results(results)
