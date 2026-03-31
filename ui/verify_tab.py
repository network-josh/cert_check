# ui/verify_tab.py

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QGroupBox, QGridLayout,
)

from core.verify_set import verify_files, check_match, scan_folder, SlotResult
from core.errors import CertToolError
from .types import LogEmitterType

_SLOTS = [
    ("key",      "Private Key",           ".key .pem"),
    ("cert",     "Certificate",           ".crt .cer .pem"),
    ("csr",      "CSR",                   ".csr .req .pem"),
    ("old_cert", "Old Certificate",       ".crt .cer .pem"),
]
_SLOT_LABELS = {s: lbl for s, lbl, _ in _SLOTS}


class VerifyTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter
        self._paths: Dict[str, str] = {}

        layout = QVBoxLayout()
        self.setLayout(layout)

        group = QGroupBox(
            "Files  (Key and Certificate required; CSR and Old Certificate optional)"
        )
        grid = QGridLayout()
        group.setLayout(grid)
        layout.addWidget(group)

        self._path_edits: Dict[str, QLineEdit] = {}
        self._hash_labels: Dict[str, QLabel] = {}

        for row, (slot, label, exts) in enumerate(_SLOTS):
            grid.addWidget(QLabel(f"{label}:"), row, 0)

            edit = QLineEdit()
            edit.setReadOnly(True)
            edit.setPlaceholderText("(none)")
            grid.addWidget(edit, row, 1)

            btn = QPushButton("Browse")
            btn.clicked.connect(
                lambda checked=False, s=slot, e=exts: self._browse(s, e)
            )
            grid.addWidget(btn, row, 2)

            hash_lbl = QLabel("")
            hash_lbl.setMinimumWidth(300)
            grid.addWidget(hash_lbl, row, 3)

            self._path_edits[slot] = edit
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
    # Slots
    # ------------------------------------------------------------------

    def _browse(self, slot: str, exts: str) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            f"Select {_SLOT_LABELS.get(slot, slot)}",
            filter=f"Certificate files ({exts});;All files (*.*)",
        )
        if path:
            self._paths[slot] = path
            self._path_edits[slot].setText(Path(path).name)
            self._hash_labels[slot].setText("")

    def _clear(self) -> None:
        self._paths.clear()
        for slot in self._path_edits:
            self._path_edits[slot].clear()
            self._hash_labels[slot].setText("")

    def _display_results(self, results: Dict[str, SlotResult]) -> None:
        for slot, (path, md5, _) in results.items():
            label     = _SLOT_LABELS.get(slot, slot)
            hash_text = f"MD5: {md5}" if md5 else "MD5: (unreadable)"
            if slot in self._hash_labels:
                self._hash_labels[slot].setText(hash_text)
            self.log_emitter.message.emit(
                f"  {label}: {Path(path).name}  —  {hash_text}", "VERIFY"
            )

        match, common = check_match(results)
        loaded = len(results)
        if loaded < 2:
            self.log_emitter.message.emit(
                "Load at least 2 files to check for a match.", "VERIFY"
            )
        elif match:
            self.log_emitter.message.emit(
                f"MATCH  (modulus MD5: {common})", "VERIFY"
            )
        else:
            self.log_emitter.message.emit(
                "MISMATCH — modulus hashes differ between files", "VERIFY"
            )

    def _run_verify(self) -> None:
        if not self._paths:
            self.log_emitter.message.emit(
                "No files selected. Use Browse or Scan Folder.", "VERIFY"
            )
            return
        self.log_emitter.message.emit("--- Verify ---", "VERIFY")
        try:
            results = verify_files(self._paths)
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
        for slot, (path, _, _) in results.items():
            if slot in self._path_edits:
                self._paths[slot] = path
                self._path_edits[slot].setText(Path(path).name)
        self._display_results(results)
