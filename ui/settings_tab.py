# ui/settings_tab.py

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QCheckBox, QLineEdit, QFileDialog,
    QGroupBox, QGridLayout, QScrollArea,
)

from .types import LogEmitterType


class SettingsTab(QWidget):
    def __init__(self, app_config: dict, commit_callback, log_emitter: LogEmitterType):
        super().__init__()
        self.app_config      = app_config
        self.commit_callback = commit_callback
        self.log_emitter     = log_emitter

        outer = QVBoxLayout()
        self.setLayout(outer)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        inner = QWidget()
        scroll.setWidget(inner)
        layout = QVBoxLayout()
        inner.setLayout(layout)

        # ── Appearance ────────────────────────────────────────────────
        ui_group = QGroupBox("Appearance")
        ui_grid  = QGridLayout()
        ui_group.setLayout(ui_grid)

        ui_grid.addWidget(QLabel("Theme:"), 0, 0)
        self.combo_theme = QComboBox()
        self.combo_theme.addItems(["light", "dark"])
        self.combo_theme.setCurrentText(app_config.get("theme", "light"))
        ui_grid.addWidget(self.combo_theme, 0, 1)

        self.chk_timestamps = QCheckBox("Show timestamps in console")
        self.chk_timestamps.setChecked(app_config.get("console_timestamps", False))
        ui_grid.addWidget(self.chk_timestamps, 1, 0, 1, 2)

        layout.addWidget(ui_group)

        # ── Paths ─────────────────────────────────────────────────────
        path_group = QGroupBox("Paths")
        path_grid  = QGridLayout()
        path_group.setLayout(path_grid)

        # Base directory — controls where cert_tool_app.json itself is saved
        path_grid.addWidget(QLabel("Base directory:"), 0, 0)
        self.edit_base_dir = QLineEdit(app_config.get("base_dir", "C:/Certs"))
        path_grid.addWidget(self.edit_base_dir, 0, 1)
        btn_base = QPushButton("Browse")
        btn_base.clicked.connect(lambda: self._browse_dir(self.edit_base_dir))
        path_grid.addWidget(btn_base, 0, 2)

        note = QLabel(
            "The config file (cert_tool_app.json) is saved inside the base directory.\n"
            "Changing this relocates the config on next Save."
        )
        note.setWordWrap(True)
        path_grid.addWidget(note, 1, 0, 1, 3)

        # Other derived paths
        self._path_edits: dict[str, QLineEdit] = {}
        derived_fields = [
            ("log_dir",            "Log directory:"),
            ("default_output_dir", "Default output directory:"),
            ("templates_dir",      "Templates directory:"),
        ]
        for row_offset, (key, label) in enumerate(derived_fields, start=2):
            path_grid.addWidget(QLabel(label), row_offset, 0)
            edit = QLineEdit(app_config.get(key, ""))
            path_grid.addWidget(edit, row_offset, 1)
            btn = QPushButton("Browse")
            btn.clicked.connect(lambda checked=False, e=edit: self._browse_dir(e))
            path_grid.addWidget(btn, row_offset, 2)
            self._path_edits[key] = edit

        layout.addWidget(path_group)

        # ── Subject Defaults ──────────────────────────────────────────
        subj_group = QGroupBox("Subject Defaults  (pre-filled when generating CSRs)")
        subj_grid  = QGridLayout()
        subj_group.setLayout(subj_grid)

        self._subj_edits: dict[str, QLineEdit] = {}
        subj_fields = [
            ("subject_country",  "Country (2-letter):"),
            ("subject_state",    "State / Province:"),
            ("subject_locality", "Locality / City:"),
            ("subject_org",      "Organization:"),
            ("subject_ou",       "Organizational Unit:"),
        ]
        for row, (key, label) in enumerate(subj_fields):
            subj_grid.addWidget(QLabel(label), row, 0)
            edit = QLineEdit(app_config.get(key, ""))
            subj_grid.addWidget(edit, row, 1)
            self._subj_edits[key] = edit

        layout.addWidget(subj_group)

        # ── CSR Defaults ──────────────────────────────────────────────
        csr_group = QGroupBox("CSR Defaults")
        csr_grid  = QGridLayout()
        csr_group.setLayout(csr_grid)

        csr_grid.addWidget(QLabel("Default key size:"), 0, 0)
        self.combo_key_size = QComboBox()
        self.combo_key_size.addItems(["2048", "4096"])
        self.combo_key_size.setCurrentText(str(app_config.get("default_key_size", 2048)))
        csr_grid.addWidget(self.combo_key_size, 0, 1)

        self.chk_dig_sig  = QCheckBox("Digital Signature (KU)")
        self.chk_key_enc  = QCheckBox("Key Encipherment (KU)")
        self.chk_srv_auth = QCheckBox("Server Authentication (EKU)")
        self.chk_cli_auth = QCheckBox("Client Authentication (EKU)")
        self.chk_dig_sig.setChecked(app_config.get("ku_digital_signature", True))
        self.chk_key_enc.setChecked(app_config.get("ku_key_encipherment", True))
        self.chk_srv_auth.setChecked(app_config.get("eku_server_auth", True))
        self.chk_cli_auth.setChecked(app_config.get("eku_client_auth", False))
        csr_grid.addWidget(self.chk_dig_sig,  1, 0)
        csr_grid.addWidget(self.chk_key_enc,  1, 1)
        csr_grid.addWidget(self.chk_srv_auth, 2, 0)
        csr_grid.addWidget(self.chk_cli_auth, 2, 1)

        layout.addWidget(csr_group)

        # ── Save ──────────────────────────────────────────────────────
        self.btn_save = QPushButton("Save Settings")
        layout.addWidget(self.btn_save)
        layout.addStretch(1)

        self.btn_save.clicked.connect(self._commit)

    # ------------------------------------------------------------------

    def _browse_dir(self, edit: QLineEdit) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Directory")
        if folder:
            edit.setText(folder)

    def _commit(self) -> None:
        self.app_config["theme"]              = self.combo_theme.currentText()
        self.app_config["console_timestamps"] = self.chk_timestamps.isChecked()

        self.app_config["base_dir"] = self.edit_base_dir.text().strip()

        for key, edit in self._path_edits.items():
            self.app_config[key] = edit.text().strip()

        for key, edit in self._subj_edits.items():
            self.app_config[key] = edit.text().strip()

        self.app_config["default_key_size"]     = int(self.combo_key_size.currentText())
        self.app_config["ku_digital_signature"] = self.chk_dig_sig.isChecked()
        self.app_config["ku_key_encipherment"]  = self.chk_key_enc.isChecked()
        self.app_config["eku_server_auth"]      = self.chk_srv_auth.isChecked()
        self.app_config["eku_client_auth"]      = self.chk_cli_auth.isChecked()

        self.commit_callback(self.app_config)
        self.log_emitter.message.emit(
            f"Settings saved to {self.app_config['base_dir']}/cert_tool_app.json",
            "SETTINGS"
        )
