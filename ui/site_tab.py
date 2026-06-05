# ui/site_tab.py

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QGroupBox, QGridLayout, QPlainTextEdit,
    QSpinBox, QApplication, QFileDialog, QCheckBox,
)

from core.app_config import load_app_config
from core.site_ops import SiteVerificationResult, verify_site, format_site_report
from core.errors import SiteVerificationError
from .types import LogEmitterType


# ─── Status color palette ─────────────────────────────────────────────────────
# GitHub-convention — high contrast on both light and dark backgrounds.
# Used by both the report highlighter and the checkbox dashboard coloring.

_COLORS_LIGHT: dict[str, str] = {
    "PASS": "#1a7f37",   # green
    "FAIL": "#c0392b",   # red
    "WARN": "#b45309",   # amber
    "INFO": "#0969da",   # blue
    "SKIP": "#6e7781",   # muted gray
}
_COLORS_DARK: dict[str, str] = {
    "PASS": "#3fb950",   # bright green
    "FAIL": "#f85149",   # bright red
    "WARN": "#d29922",   # gold
    "INFO": "#58a6ff",   # sky blue
    "SKIP": "#8b949e",   # soft gray
}

# Severity used to pick the worst status for group header coloring.
_STATUS_SEVERITY: dict[str, int] = {
    "FAIL": 4, "WARN": 3, "INFO": 2, "PASS": 1, "SKIP": 0,
}

# Maps each check_id to the SiteCheckResult.name string returned by core/site_ops.py.
# The TLS names come from _probe_tls_version's check_name format string.
_ID_TO_RESULT_NAME: dict[str, str] = {
    "expiry":      "Certificate expiration",
    "san_cn":      "SAN/CN match",
    "self_signed": "Self-signed certificate",
    "full_chain":  "Full chain served",
    "chain_order": "Chain order",
    "trusted_ca":  "Trusted CA",
    "weak_sig":    "Signature algorithm",
    "key_size":    "Key size",
    "ocsp_staple": "OCSP stapling",
    "ocsp":        "OCSP revocation",
    "crl":         "CRL revocation",
    "tls10":       "TLS rejected: TLS 1.0",
    "tls11":       "TLS rejected: TLS 1.1",
    "tls12":       "TLS supported: TLS 1.2",
    "tls13":       "TLS supported: TLS 1.3",
}


# ─── Report syntax highlighter ────────────────────────────────────────────────

class _StatusHighlighter(QSyntaxHighlighter):
    """Colors full lines that begin with a [STATUS] tag in the report panel."""

    _PATTERN = re.compile(r'^\[(PASS|FAIL|WARN|INFO|SKIP)\s*\]')

    def __init__(self, document):
        super().__init__(document)
        self._is_dark = False

    def update_theme(self, is_dark: bool) -> None:
        self._is_dark = is_dark

    def highlightBlock(self, text: str) -> None:
        m = self._PATTERN.match(text)
        if not m:
            return
        color_hex = (_COLORS_DARK if self._is_dark else _COLORS_LIGHT).get(m.group(1))
        if not color_hex:
            return
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color_hex))
        self.setFormat(0, len(text), fmt)


# ─── Check groups definition ──────────────────────────────────────────────────

_CHECK_GROUPS = [
    ("General", [
        ("expiry",       "Certificate expiration"),
        ("san_cn",       "SAN / CN match"),
        ("self_signed",  "Self-signed detection"),
        ("full_chain",   "Full chain served"),
        ("chain_order",  "Chain order"),
    ]),
    ("Security", [
        ("trusted_ca",  "Trusted CA"),
        ("weak_sig",    "Weak signature"),
        ("key_size",    "Key size"),
    ]),
    ("Revocation", [
        ("ocsp_staple", "OCSP stapling"),
        ("ocsp",        "OCSP revocation"),
        ("crl",         "CRL revocation"),
    ]),
    ("TLS Versions", [
        ("tls10",  "TLS 1.0 rejected"),
        ("tls11",  "TLS 1.1 rejected"),
        ("tls12",  "TLS 1.2 supported"),
        ("tls13",  "TLS 1.3 supported"),
    ]),
]


# ─── Background worker ────────────────────────────────────────────────────────

class _SiteCheckWorker(QObject):
    progress = Signal(str)
    finished = Signal(object)  # SiteVerificationResult
    failed   = Signal(str)

    def __init__(self, hostname, port, ip_override, expiry_warn_days,
                 timeout, ocsp_staple_severity, enabled_checks):
        super().__init__()
        self._hostname         = hostname
        self._port             = port
        self._ip_override      = ip_override or None
        self._expiry_warn_days = expiry_warn_days
        self._timeout          = timeout
        self._ocsp_staple_sev  = ocsp_staple_severity
        self._enabled_checks   = enabled_checks

    def run(self) -> None:
        try:
            result = verify_site(
                hostname=self._hostname,
                port=self._port,
                ip_override=self._ip_override,
                expiry_warn_days=self._expiry_warn_days,
                timeout=self._timeout,
                ocsp_staple_severity=self._ocsp_staple_sev,
                enabled_checks=self._enabled_checks,
                log_callback=lambda m: self.progress.emit(m),
            )
            self.finished.emit(result)
        except SiteVerificationError as e:
            self.failed.emit(str(e))
        except Exception as e:
            self.failed.emit(f"Unexpected error: {e}")


# ─── Tab widget ───────────────────────────────────────────────────────────────

class SiteTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter  = log_emitter
        self._last_report = ""
        self._thread: Optional[QThread] = None
        self._worker: Optional[_SiteCheckWorker] = None

        self._group_headers: dict[str, QCheckBox] = {}
        self._group_checks:  dict[str, list[QCheckBox]] = {}
        self._check_cbs:     dict[str, QCheckBox] = {}
        self._updating = False

        layout = QVBoxLayout()
        self.setLayout(layout)

        # ── Connection inputs ─────────────────────────────────────────────────
        conn_group = QGroupBox("Connection")
        conn_grid  = QGridLayout()
        conn_group.setLayout(conn_grid)

        conn_grid.addWidget(QLabel("Hostname (SNI):"), 0, 0)
        self.edit_hostname = QLineEdit()
        self.edit_hostname.setPlaceholderText("example.com")
        conn_grid.addWidget(self.edit_hostname, 0, 1)

        conn_grid.addWidget(QLabel("IP address (optional):"), 1, 0)
        self.edit_ip = QLineEdit()
        self.edit_ip.setPlaceholderText("(use DNS)")
        conn_grid.addWidget(self.edit_ip, 1, 1)

        right_row = QHBoxLayout()
        right_row.addWidget(QLabel("Port:"))
        self.spin_port = QSpinBox()
        self.spin_port.setRange(1, 65535)
        self.spin_port.setValue(443)
        right_row.addWidget(self.spin_port)
        right_row.addSpacing(20)
        right_row.addWidget(QLabel("Expiry warn:"))
        self.spin_warn_days = QSpinBox()
        self.spin_warn_days.setRange(1, 365)
        self.spin_warn_days.setSuffix(" days")
        right_row.addWidget(self.spin_warn_days)
        right_row.addStretch(1)
        conn_grid.addLayout(right_row, 2, 0, 1, 2)

        run_row = QHBoxLayout()
        self.btn_run = QPushButton("Run Checks")
        run_row.addWidget(self.btn_run)
        run_row.addStretch(1)
        conn_grid.addLayout(run_row, 3, 0, 1, 2)

        layout.addWidget(conn_group)

        # ── Check selection (doubles as results dashboard) ────────────────────
        layout.addWidget(self._build_checks_ui())

        # ── Overall status label ──────────────────────────────────────────────
        self.lbl_overall = QLabel("")
        layout.addWidget(self.lbl_overall)

        # ── Report view ───────────────────────────────────────────────────────
        self.report_view = QPlainTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setMinimumHeight(200)
        self.report_view.setPlaceholderText("Verification report will appear here.")
        layout.addWidget(self.report_view)
        self._highlighter = _StatusHighlighter(self.report_view.document())

        # ── Export row ────────────────────────────────────────────────────────
        export_row = QHBoxLayout()
        self.btn_copy   = QPushButton("Copy Report")
        self.btn_export = QPushButton("Export Report…")
        self.btn_copy.setEnabled(False)
        self.btn_export.setEnabled(False)
        export_row.addWidget(self.btn_copy)
        export_row.addWidget(self.btn_export)
        export_row.addStretch(1)
        layout.addLayout(export_row)

        layout.addStretch(1)

        # ── Wire signals ──────────────────────────────────────────────────────
        self.btn_run.clicked.connect(self._start_checks)
        self.edit_hostname.returnPressed.connect(self._start_checks)
        self.edit_hostname.textChanged.connect(self._on_hostname_changed)
        self.btn_copy.clicked.connect(self._copy_report)
        self.btn_export.clicked.connect(self._export_report)

        self._load_defaults()

    # ── Check selection UI ────────────────────────────────────────────────────

    def _build_checks_ui(self) -> QGroupBox:
        outer = QGroupBox("Checks")
        outer_layout = QHBoxLayout()
        outer.setLayout(outer_layout)

        for group_name, check_defs in _CHECK_GROUPS:
            group_box = QGroupBox(group_name)
            vbox = QVBoxLayout()
            group_box.setLayout(vbox)

            all_cb = QCheckBox("All")
            all_cb.setChecked(True)
            vbox.addWidget(all_cb)
            self._group_headers[group_name] = all_cb

            cbs: list[QCheckBox] = []
            for check_id, check_label in check_defs:
                cb = QCheckBox(check_label)
                cb.setChecked(True)
                vbox.addWidget(cb)
                cbs.append(cb)
                self._check_cbs[check_id] = cb
                cb.toggled.connect(
                    lambda _checked, gn=group_name: self._on_individual_toggled(gn)
                )

            self._group_checks[group_name] = cbs
            vbox.addStretch(1)

            all_cb.toggled.connect(
                lambda checked, gn=group_name: self._on_group_all_toggled(gn, checked)
            )

            outer_layout.addWidget(group_box)

        return outer

    def _on_group_all_toggled(self, group_name: str, checked: bool) -> None:
        if self._updating:
            return
        self._updating = True
        for cb in self._group_checks[group_name]:
            cb.setChecked(checked)
        self._updating = False

    def _on_individual_toggled(self, group_name: str) -> None:
        if self._updating:
            return
        all_checked = all(cb.isChecked() for cb in self._group_checks[group_name])
        self._updating = True
        self._group_headers[group_name].setChecked(all_checked)
        self._updating = False

    def _get_enabled_checks(self) -> set[str]:
        return {cid for cid, cb in self._check_cbs.items() if cb.isChecked()}

    # ── Dashboard coloring ────────────────────────────────────────────────────

    def _reset_check_colors(self) -> None:
        for cb in self._check_cbs.values():
            cb.setStyleSheet("")
        for cb in self._group_headers.values():
            cb.setStyleSheet("")

    def _apply_check_colors(
        self, result: SiteVerificationResult, is_dark: bool
    ) -> None:
        colors = _COLORS_DARK if is_dark else _COLORS_LIGHT

        # Build result-name → status lookup from this run
        name_to_status = {c.name: c.status for c in result.checks}

        # Color individual check checkboxes
        for check_id, cb in self._check_cbs.items():
            result_name = _ID_TO_RESULT_NAME.get(check_id)
            status = name_to_status.get(result_name) if result_name else None
            if status and status in colors:
                cb.setStyleSheet(f"QCheckBox {{ color: {colors[status]}; }}")
            else:
                cb.setStyleSheet("")  # not run — leave default

        # Color each group header with the worst status in that group
        for group_name, group_defs in _CHECK_GROUPS:
            statuses = [
                name_to_status[_ID_TO_RESULT_NAME[cid]]
                for cid, _ in group_defs
                if cid in _ID_TO_RESULT_NAME
                and _ID_TO_RESULT_NAME[cid] in name_to_status
            ]
            if not statuses:
                self._group_headers[group_name].setStyleSheet("")
                continue
            worst = max(statuses, key=lambda s: _STATUS_SEVERITY.get(s, 0))
            color_hex = colors.get(worst, "")
            if color_hex:
                self._group_headers[group_name].setStyleSheet(
                    f"QCheckBox {{ color: {color_hex}; }}"
                )
            else:
                self._group_headers[group_name].setStyleSheet("")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        self.log_emitter.message.emit(msg, "SITE")

    def _load_defaults(self) -> None:
        cfg = load_app_config()
        self.spin_warn_days.setValue(cfg.get("site_expiry_warn_days", 30))

    def _on_hostname_changed(self) -> None:
        if self._last_report:
            self.report_view.clear()
            self._last_report = ""
            self.lbl_overall.setText("")
            self.btn_copy.setEnabled(False)
            self.btn_export.setEnabled(False)
            self._reset_check_colors()

    # ── Run checks ────────────────────────────────────────────────────────────

    def _start_checks(self) -> None:
        hostname = self.edit_hostname.text().strip()
        if not hostname:
            self._log("Enter a hostname first.")
            return
        if self._thread is not None:
            self._log("A check is already running.")
            return

        enabled = self._get_enabled_checks()
        if not enabled:
            self._log("Select at least one check to run.")
            return

        cfg         = load_app_config()
        timeout     = cfg.get("site_check_timeout", 10)
        staple_sev  = cfg.get("site_ocsp_staple_severity", "INFO")
        ip_override = self.edit_ip.text().strip()
        port        = self.spin_port.value()
        expiry_warn = self.spin_warn_days.value()

        self.btn_run.setEnabled(False)
        self.lbl_overall.setText("Running…")
        self.report_view.clear()
        self.btn_copy.setEnabled(False)
        self.btn_export.setEnabled(False)
        self._last_report = ""
        self._reset_check_colors()

        self._log(f"--- Site Verification: {hostname}:{port} ({len(enabled)} checks) ---")

        self._thread = QThread()
        self._worker = _SiteCheckWorker(
            hostname, port, ip_override, expiry_warn, timeout, staple_sev, enabled
        )
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._log)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._clear_thread)

        self._thread.start()

    def _clear_thread(self) -> None:
        self._thread = None
        self._worker = None

    def _on_finished(self, result: SiteVerificationResult) -> None:
        self.btn_run.setEnabled(True)
        cfg = load_app_config()
        is_dark = cfg.get("theme", "light") == "dark"

        self._highlighter.update_theme(is_dark)
        report = format_site_report(result)
        self._last_report = report
        self.report_view.setPlainText(report)

        self._apply_check_colors(result, is_dark)

        self.lbl_overall.setText(f"Overall: {result.overall}")
        self.btn_copy.setEnabled(True)
        self.btn_export.setEnabled(True)

        for check in result.checks:
            self._log(f"  [{check.status:<4}] {check.name}: {check.detail}")
        self._log(f"Site verification complete: {result.overall}")

    def _on_failed(self, error_msg: str) -> None:
        self.btn_run.setEnabled(True)
        self.lbl_overall.setText("Overall: ERROR")
        self._log(f"Site verification failed: {error_msg}")

    # ── Copy / export ─────────────────────────────────────────────────────────

    def _copy_report(self) -> None:
        if self._last_report:
            QApplication.clipboard().setText(self._last_report)
            self._log("Site verification report copied to clipboard.")

    def _export_report(self) -> None:
        if not self._last_report:
            return
        cfg       = load_app_config()
        out_dir   = cfg.get("default_output_dir", "C:/Certs")
        hostname  = self.edit_hostname.text().strip().replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default   = str(Path(out_dir) / f"site_verify_{hostname}_{timestamp}.txt")
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Verification Report", default,
            "Text files (*.txt);;All files (*.*)",
        )
        if not save_path:
            return
        try:
            Path(save_path).write_text(self._last_report, encoding="utf-8")
        except Exception as e:
            self._log(f"Failed to export report: {e}")
            return
        self._log(f"Site verification report exported: {save_path}")
