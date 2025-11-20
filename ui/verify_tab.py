# ui/verify_tab.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit

class VerifyTab(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.btn = QPushButton("Verify Cert/Key/CSR Set")
        self.output = QTextEdit()

        layout.addWidget(self.btn)
        layout.addWidget(self.output)
