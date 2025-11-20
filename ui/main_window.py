# ui/main_window.py
from PySide6.QtWidgets import QMainWindow, QTabWidget

from ui.verify_tab import VerifyTab
from ui.san_tab import SanTab
from ui.csr_tab import CsrTab
from ui.chain_tab import ChainTab
from ui.settings_tab import SettingsTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Certificate Tool")

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tabs.addTab(VerifyTab(), "Verify Set")
        self.tabs.addTab(SanTab(), "SAN Generator")
        self.tabs.addTab(CsrTab(), "Create CSR")
        self.tabs.addTab(ChainTab(), "Chain Helper")
        self.tabs.addTab(SettingsTab(), "Settings")
