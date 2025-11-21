# ui/verify_tab.py

from __future__ import annotations
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog

from core.verify_set import verify_folder
from core.errors import CertToolError
from .types import LogEmitterType


class VerifyTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.btn_select = QPushButton("Select Folder and Verify Cert/Key/CSR Set")
        layout.addWidget(self.btn_select)

        self.btn_select.clicked.connect(self.run_verify)

    def run_verify(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder with Certs/Keys")
        if not folder:
            return
        try:
            result = verify_folder(folder)
        except CertToolError as e:
            self.log_emitter.message.emit(f"Error verifying folder: {e}", "VERIFY")
            return

        if not result:
            self.log_emitter.message.emit(
                f"No valid cert/key/CSR files found in {folder}",
                "VERIFY"
            )
            return

        # Simple textual interpretation; the detailed modulus comparison
        # logic can be expanded here or in verify_set.py
        self.log_emitter.message.emit(f"Verified items in {folder}:", "VERIFY")
        for kind, (path, modulus) in result.items():
            self.log_emitter.message.emit(f"  {kind}: {path}", "VERIFY")
