# ui/chain_tab.py

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QGroupBox, QGridLayout,
    QPlainTextEdit, QCheckBox, QApplication,
)

from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from core.app_config import load_app_config
from core.chain_ops import (
    load_leaf_cert, find_chain_candidates,
    build_chain_via_aia, write_chain_pem,
    load_chain_pem, validate_chain, format_validation_report,
    _cert_not_after, _format_fingerprint,
)
from core.errors import CertToolError, ChainFetchError
from .types import LogEmitterType


def _safe_filename(text: str) -> str:
    """Strip characters that are illegal in Windows filenames."""
    return re.sub(r'[\\/:*?"<>|]', "_", text)


class ChainTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter

        self._leaf_cert = None
        self._leaf_path: str = ""
        self._built_chain: Optional[List] = None
        self._last_report: str = ""

        layout = QVBoxLayout()
        self.setLayout(layout)

        # ── Shared leaf section ───────────────────────────────────────────────
        leaf_group  = QGroupBox("Leaf Certificate")
        leaf_grid   = QGridLayout()
        leaf_group.setLayout(leaf_grid)

        self.edit_leaf_path = QLineEdit()
        self.edit_leaf_path.setReadOnly(True)
        self.edit_leaf_path.setPlaceholderText("(no certificate loaded)")
        leaf_grid.addWidget(self.edit_leaf_path, 0, 0)

        self.btn_load_leaf = QPushButton("Load Leaf")
        leaf_grid.addWidget(self.btn_load_leaf, 0, 1)

        self.lbl_leaf_info = QLabel("")
        self.lbl_leaf_info.setWordWrap(True)
        leaf_grid.addWidget(self.lbl_leaf_info, 1, 0, 1, 2)

        layout.addWidget(leaf_group)

        # ── Scan local folder (original feature) ─────────────────────────────
        scan_group  = QGroupBox("Scan Local Folder")
        scan_layout = QHBoxLayout()
        scan_group.setLayout(scan_layout)

        self.btn_scan = QPushButton("Scan Folder for Chain Certs")
        scan_layout.addWidget(self.btn_scan)
        scan_layout.addStretch(1)

        layout.addWidget(scan_group)

        # ── Build chain via AIA ───────────────────────────────────────────────
        build_group  = QGroupBox("Build Chain via AIA")
        build_layout = QVBoxLayout()
        build_group.setLayout(build_layout)

        build_btn_row = QHBoxLayout()
        self.btn_build = QPushButton("Build Chain")
        build_btn_row.addWidget(self.btn_build)
        build_btn_row.addStretch(1)
        build_layout.addLayout(build_btn_row)

        out_row = QHBoxLayout()
        out_row.addWidget(QLabel("Output directory:"))
        self.edit_chain_out_dir = QLineEdit()
        out_row.addWidget(self.edit_chain_out_dir)
        self.btn_browse_out = QPushButton("Browse")
        out_row.addWidget(self.btn_browse_out)
        build_layout.addLayout(out_row)

        self.chk_include_leaf = QCheckBox("Include leaf certificate in output PEM")
        build_layout.addWidget(self.chk_include_leaf)

        save_row = QHBoxLayout()
        self.btn_save_chain = QPushButton("Save Chain PEM")
        self.btn_save_chain.setEnabled(False)
        save_row.addWidget(self.btn_save_chain)
        save_row.addStretch(1)
        build_layout.addLayout(save_row)

        layout.addWidget(build_group)

        # ── Validate chain ────────────────────────────────────────────────────
        val_group  = QGroupBox("Validate Chain")
        val_layout = QVBoxLayout()
        val_group.setLayout(val_layout)

        chain_row = QGridLayout()
        chain_row.addWidget(QLabel("Chain PEM:"), 0, 0)
        self.edit_chain_path = QLineEdit()
        self.edit_chain_path.setReadOnly(True)
        self.edit_chain_path.setPlaceholderText("(no chain file loaded)")
        chain_row.addWidget(self.edit_chain_path, 0, 1)
        self.btn_browse_chain = QPushButton("Browse")
        chain_row.addWidget(self.btn_browse_chain, 0, 2)
        val_layout.addLayout(chain_row)

        val_btn_row = QHBoxLayout()
        self.btn_validate = QPushButton("Validate Chain")
        val_btn_row.addWidget(self.btn_validate)
        val_btn_row.addStretch(1)
        val_layout.addLayout(val_btn_row)

        self.report_view = QPlainTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setMinimumHeight(200)
        self.report_view.setPlaceholderText("Validation report will appear here.")
        val_layout.addWidget(self.report_view)

        export_row = QHBoxLayout()
        self.btn_copy_report = QPushButton("Copy Report")
        self.btn_copy_report.setEnabled(False)
        self.btn_export_report = QPushButton("Export Report…")
        self.btn_export_report.setEnabled(False)
        export_row.addWidget(self.btn_copy_report)
        export_row.addWidget(self.btn_export_report)
        export_row.addStretch(1)
        val_layout.addLayout(export_row)

        layout.addWidget(val_group)
        layout.addStretch(1)

        # ── Wire signals ──────────────────────────────────────────────────────
        self.btn_load_leaf.clicked.connect(self._load_leaf)
        self.btn_scan.clicked.connect(self._scan_folder)
        self.btn_build.clicked.connect(self._build_chain)
        self.btn_browse_out.clicked.connect(self._browse_out_dir)
        self.btn_save_chain.clicked.connect(self._save_chain)
        self.btn_browse_chain.clicked.connect(self._browse_chain_file)
        self.btn_validate.clicked.connect(self._validate)
        self.btn_copy_report.clicked.connect(self._copy_report)
        self.btn_export_report.clicked.connect(self._export_report)

        self._load_default_out_dir()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        self.log_emitter.message.emit(msg, "CHAIN")

    def _load_default_out_dir(self) -> None:
        cfg = load_app_config()
        self.edit_chain_out_dir.setText(cfg.get("default_output_dir", "C:/Certs"))

    def _update_leaf_info(self) -> None:
        """Refresh the leaf info label after loading a new leaf cert."""
        if self._leaf_cert is None:
            self.lbl_leaf_info.setText("")
            return
        cert = self._leaf_cert
        cn = ""
        try:
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    cn = attr.value
                    break
        except Exception:
            pass
        na = _cert_not_after(cert)
        fp = _format_fingerprint(cert.fingerprint(hashes.SHA256()))
        self.lbl_leaf_info.setText(
            f"CN={cn}  |  Expires: {na.date()}  |  SHA-256: {fp}"
        )

    # ── Shared leaf load ──────────────────────────────────────────────────────

    def _load_leaf(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Leaf Certificate",
            filter="Certificates (*.crt *.cer *.pem *.der);;All files (*.*)",
        )
        if not path:
            return
        try:
            self._leaf_cert = load_leaf_cert(path)
            self._leaf_path = path
            self.edit_leaf_path.setText(path)
            self._update_leaf_info()
            self._log(f"Loaded leaf certificate: {path}")
        except Exception as e:
            self._log(f"Failed to load leaf cert: {e}")

    # ── Scan local folder ─────────────────────────────────────────────────────

    def _scan_folder(self) -> None:
        if self._leaf_cert is None:
            self._log("Load a leaf certificate first.")
            return
        folder = QFileDialog.getExistingDirectory(self, "Select Folder of Chain Certificates")
        if not folder:
            return
        try:
            results = find_chain_candidates(self._leaf_cert, folder)
        except CertToolError as e:
            self._log(f"Error scanning folder: {e}")
            return
        if not results:
            self._log("No chain candidates found.")
            return
        self._log("Chain candidates found:")
        for c in results:
            tags = []
            if c.issuer_match: tags.append("issuer-match")
            if c.aki_match:    tags.append("aki-match")
            label = ", ".join(tags) if tags else "weak match"
            self._log(f"  {c.path}  →  {label}")

    # ── Build chain via AIA ───────────────────────────────────────────────────

    def _browse_out_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self.edit_chain_out_dir.setText(folder)

    def _build_chain(self) -> None:
        if self._leaf_cert is None:
            self._log("Load a leaf certificate first.")
            return
        cfg = load_app_config()
        timeout = cfg.get("aia_fetch_timeout", 10)
        self._log("Fetching certificate chain via AIA…")
        try:
            chain = build_chain_via_aia(
                self._leaf_cert,
                timeout=timeout,
                log_callback=self._log,
            )
        except ChainFetchError as e:
            self._log(f"AIA fetch failed: {e}")
            return
        except CertToolError as e:
            self._log(f"Chain build failed: {e}")
            return
        self._built_chain = chain
        self.btn_save_chain.setEnabled(True)
        n_intermediates = sum(
            1 for c in chain
            if c.subject.rfc4514_string() != c.issuer.rfc4514_string()
        )
        has_root = chain and chain[-1].subject == chain[-1].issuer
        self._log(
            f"Chain built: {len(chain)} cert(s) "
            f"({n_intermediates} intermediate(s)"
            + (", 1 root" if has_root else ", root not found")
            + "). Click 'Save Chain PEM' to write to disk."
        )

    def _save_chain(self) -> None:
        if not self._built_chain:
            self._log("Build a chain first.")
            return
        out_dir = self.edit_chain_out_dir.text().strip() or "C:/Certs"
        cn_raw = ""
        if self._leaf_cert:
            try:
                for attr in self._leaf_cert.subject:
                    if attr.oid == NameOID.COMMON_NAME:
                        cn_raw = attr.value
                        break
            except Exception:
                pass
        default_name = f"{_safe_filename(cn_raw) or 'leaf'}-chain.pem"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save Chain PEM",
            str(Path(out_dir) / default_name),
            "PEM files (*.pem);;All files (*.*)",
        )
        if not save_path:
            return
        include_leaf = self.chk_include_leaf.isChecked()
        try:
            write_chain_pem(
                self._built_chain,
                Path(save_path),
                include_leaf=include_leaf,
                leaf=self._leaf_cert if include_leaf else None,
            )
        except Exception as e:
            self._log(f"Failed to save chain PEM: {e}")
            return
        self._log(f"Chain PEM saved: {save_path}")
        # Auto-populate the validator's chain path field
        self.edit_chain_path.setText(save_path)

    # ── Validate chain ────────────────────────────────────────────────────────

    def _browse_chain_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Chain PEM",
            filter="PEM files (*.pem *.crt *.cer);;All files (*.*)",
        )
        if path:
            self.edit_chain_path.setText(path)

    def _validate(self) -> None:
        if self._leaf_cert is None:
            self._log("Load a leaf certificate first.")
            return
        chain_path = self.edit_chain_path.text().strip()
        if not chain_path:
            self._log("Browse to a chain PEM file first.")
            return
        try:
            chain_certs = load_chain_pem(chain_path)
        except CertToolError as e:
            self._log(f"Failed to load chain PEM: {e}")
            return
        result = validate_chain(self._leaf_cert, chain_certs)
        report = format_validation_report(self._leaf_path, chain_path, result)
        self._last_report = report
        self.report_view.setPlainText(report)
        self.btn_copy_report.setEnabled(True)
        self.btn_export_report.setEnabled(True)
        self._log(f"Validation complete: {result.overall}")

    def _copy_report(self) -> None:
        if self._last_report:
            QApplication.clipboard().setText(self._last_report)
            self._log("Validation report copied to clipboard.")

    def _export_report(self) -> None:
        if not self._last_report:
            return
        cfg = load_app_config()
        out_dir = cfg.get("default_output_dir", "C:/Certs")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"chain_validation_{timestamp}.txt"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Validation Report",
            str(Path(out_dir) / default_name),
            "Text files (*.txt);;All files (*.*)",
        )
        if not save_path:
            return
        try:
            Path(save_path).write_text(self._last_report, encoding="utf-8")
        except Exception as e:
            self._log(f"Failed to export report: {e}")
            return
        self._log(f"Validation report exported: {save_path}")
