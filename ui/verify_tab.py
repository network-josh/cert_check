# ui/verify_tab.py

from __future__ import annotations

from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog

from core.cert_inspector import analyze_folder, VerificationPolicy, Severity
from core.errors import CertToolError
from .types import LogEmitterType


class VerifyTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.btn_select = QPushButton("Select Folder and Verify Certificates")
        layout.addWidget(self.btn_select)

        self.btn_select.clicked.connect(self.run_verify)

    def run_verify(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder with Certificates")
        if not folder:
            return

        policy = VerificationPolicy(
            san_missing_severity=Severity.ERROR,
            san_added_severity=Severity.WARN,
            ext_missing_severity=Severity.WARN,
            exp_soon_days=30,
            exp_soon_severity=Severity.WARN,
        )

        try:
            result = analyze_folder(folder, policy)
        except CertToolError as e:
            self.log_emitter.message.emit(f"Error analyzing folder: {e}", "VERIFY")
            return

        # High-level summary
        if result.ok:
            self.log_emitter.message.emit(
                f"Folder '{folder}' verification: OK (with warnings possible, see below).",
                "VERIFY"
            )
        else:
            self.log_emitter.message.emit(
                f"Folder '{folder}' verification: FAIL (see details below).",
                "VERIFY"
            )

        # Issues
        for issue in result.issues:
            prefix = f"{issue.severity}"
            self.log_emitter.message.emit(f"{prefix}: {issue.message}", "VERIFY")

        # CA candidates in folder
        if result.ca_candidates:
            self.log_emitter.message.emit("Potential chain/CA certs in folder:", "VERIFY")
            for ca in result.ca_candidates:
                self.log_emitter.message.emit(
                    f"  {ca.path.name} (Subject CN={ca.cn}, Issuer={ca.issuer})",
                    "VERIFY"
                )
