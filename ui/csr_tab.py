# ui/csr_tab.py

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QComboBox, QListWidget,
    QCheckBox, QGroupBox, QGridLayout,
)

from core.app_config import load_app_config
from core.csr_ops import (
    generate_csr_and_keys, CsrSpec,
    SubjectDefaults, KeyUsageDefaults, EkuDefaults,
)
from core.csr_templates import list_templates, load_template, save_template
from core.san_ops import parse_user_sans, SanEntry, SanType
from core.errors import CertToolError
from .types import LogEmitterType


class CsrTab(QWidget):
    def __init__(self, log_emitter: LogEmitterType):
        super().__init__()
        self.log_emitter = log_emitter
        self._sans: List[SanEntry] = []

        layout = QVBoxLayout()
        self.setLayout(layout)

        # ── Template ──────────────────────────────────────────────────
        tpl_group = QGroupBox("Template")
        tpl_layout = QHBoxLayout()
        tpl_group.setLayout(tpl_layout)

        tpl_layout.addWidget(QLabel("Load:"))
        self.combo_templates = QComboBox()
        self.combo_templates.setMinimumWidth(160)
        tpl_layout.addWidget(self.combo_templates)
        self.btn_load_tpl = QPushButton("Load")
        tpl_layout.addWidget(self.btn_load_tpl)

        tpl_layout.addSpacing(20)

        tpl_layout.addWidget(QLabel("Save as:"))
        self.edit_tpl_name = QLineEdit()
        self.edit_tpl_name.setPlaceholderText("template name")
        self.edit_tpl_name.setMaximumWidth(160)
        tpl_layout.addWidget(self.edit_tpl_name)
        self.btn_save_tpl = QPushButton("Save Template")
        tpl_layout.addWidget(self.btn_save_tpl)

        tpl_layout.addStretch(1)
        layout.addWidget(tpl_group)

        # ── Common Name + SANs ────────────────────────────────────────
        san_group = QGroupBox("Common Name and Subject Alternative Names")
        san_layout = QVBoxLayout()
        san_group.setLayout(san_layout)

        cn_row = QHBoxLayout()
        cn_row.addWidget(QLabel("Common Name:"))
        self.edit_cn = QLineEdit()
        cn_row.addWidget(self.edit_cn)
        san_layout.addLayout(cn_row)

        san_input_row = QHBoxLayout()
        self.edit_san_entry = QLineEdit()
        self.edit_san_entry.setPlaceholderText("hostname or IP address")
        san_input_row.addWidget(self.edit_san_entry)
        self.btn_add_san    = QPushButton("Add")
        self.btn_seed_sans  = QPushButton("Seed CN + www")
        self.btn_remove_san = QPushButton("Remove Selected")
        san_input_row.addWidget(self.btn_add_san)
        san_input_row.addWidget(self.btn_seed_sans)
        san_input_row.addWidget(self.btn_remove_san)
        san_layout.addLayout(san_input_row)

        self.san_list = QListWidget()
        self.san_list.setFixedHeight(100)
        san_layout.addWidget(self.san_list)

        layout.addWidget(san_group)

        # ── Key & Usage ───────────────────────────────────────────────
        key_group = QGroupBox("Key and Usage")
        key_grid = QGridLayout()
        key_group.setLayout(key_grid)

        key_grid.addWidget(QLabel("Key Size:"), 0, 0)
        self.combo_key_size = QComboBox()
        self.combo_key_size.addItems(["2048", "4096"])
        key_grid.addWidget(self.combo_key_size, 0, 1)

        self.chk_dig_sig  = QCheckBox("Digital Signature (KU)")
        self.chk_key_enc  = QCheckBox("Key Encipherment (KU)")
        self.chk_srv_auth = QCheckBox("Server Authentication (EKU)")
        self.chk_cli_auth = QCheckBox("Client Authentication (EKU)")
        key_grid.addWidget(self.chk_dig_sig,  1, 0)
        key_grid.addWidget(self.chk_key_enc,  1, 1)
        key_grid.addWidget(self.chk_srv_auth, 2, 0)
        key_grid.addWidget(self.chk_cli_auth, 2, 1)

        layout.addWidget(key_group)

        # ── Output ────────────────────────────────────────────────────
        out_group = QGroupBox("Output")
        out_layout = QVBoxLayout()
        out_group.setLayout(out_layout)

        out_dir_row = QHBoxLayout()
        out_dir_row.addWidget(QLabel("Directory:"))
        self.edit_out_dir = QLineEdit()
        out_dir_row.addWidget(self.edit_out_dir)
        self.btn_browse_out = QPushButton("Browse")
        out_dir_row.addWidget(self.btn_browse_out)
        out_layout.addLayout(out_dir_row)

        pw_row = QHBoxLayout()
        self.chk_encrypt_key = QCheckBox("Password-protect key:")
        self.edit_password = QLineEdit()
        self.edit_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit_password.setEnabled(False)
        self.edit_password.setPlaceholderText("password")
        pw_row.addWidget(self.chk_encrypt_key)
        pw_row.addWidget(self.edit_password)
        out_layout.addLayout(pw_row)

        layout.addWidget(out_group)

        # ── Generate ──────────────────────────────────────────────────
        self.btn_generate = QPushButton("Generate CSR + Key")
        layout.addWidget(self.btn_generate)
        layout.addStretch(1)

        # ── Wire signals ──────────────────────────────────────────────
        self.btn_load_tpl.clicked.connect(self._load_template)
        self.btn_save_tpl.clicked.connect(self._save_template)
        self.btn_add_san.clicked.connect(self._add_san)
        self.btn_seed_sans.clicked.connect(self._seed_sans)
        self.btn_remove_san.clicked.connect(self._remove_san)
        self.btn_browse_out.clicked.connect(self._browse_output)
        self.chk_encrypt_key.toggled.connect(self.edit_password.setEnabled)
        self.btn_generate.clicked.connect(self._generate)
        self.edit_san_entry.returnPressed.connect(self._add_san)

        self._load_defaults()
        self._refresh_templates()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_defaults(self) -> None:
        cfg = load_app_config()
        self.edit_out_dir.setText(cfg.get("default_output_dir", "C:/Certs"))
        size = str(cfg.get("default_key_size", 2048))
        idx = self.combo_key_size.findText(size)
        if idx >= 0:
            self.combo_key_size.setCurrentIndex(idx)
        self.chk_dig_sig.setChecked(cfg.get("ku_digital_signature", True))
        self.chk_key_enc.setChecked(cfg.get("ku_key_encipherment", True))
        self.chk_srv_auth.setChecked(cfg.get("eku_server_auth", True))
        self.chk_cli_auth.setChecked(cfg.get("eku_client_auth", False))

    def _refresh_templates(self) -> None:
        self.combo_templates.clear()
        self.combo_templates.addItems(list_templates())

    def _refresh_san_list(self) -> None:
        self.san_list.clear()
        for san in self._sans:
            self.san_list.addItem(f"{san.type.value}={san.value}")

    # ------------------------------------------------------------------
    # Template slots
    # ------------------------------------------------------------------

    def _load_template(self) -> None:
        name = self.combo_templates.currentText().strip()
        if not name:
            self.log_emitter.message.emit("No template selected.", "CSR")
            return
        data = load_template(name)
        if not data:
            self.log_emitter.message.emit(f"Template '{name}' not found.", "CSR")
            return
        ku  = data.get("key_usage", {})
        eku = data.get("eku", {})
        self.chk_dig_sig.setChecked(ku.get("digital_signature", True))
        self.chk_key_enc.setChecked(ku.get("key_encipherment", True))
        self.chk_srv_auth.setChecked(eku.get("server_auth", True))
        self.chk_cli_auth.setChecked(eku.get("client_auth", False))
        idx = self.combo_key_size.findText(str(data.get("key_size", 2048)))
        if idx >= 0:
            self.combo_key_size.setCurrentIndex(idx)
        self.log_emitter.message.emit(f"Loaded template '{name}'.", "CSR")

    def _save_template(self) -> None:
        name = self.edit_tpl_name.text().strip()
        if not name:
            self.log_emitter.message.emit(
                "Enter a template name in the 'Save as' field first.", "CSR"
            )
            return
        cfg = load_app_config()
        subject = SubjectDefaults(
            country=cfg.get("subject_country") or None,
            state=cfg.get("subject_state") or None,
            locality=cfg.get("subject_locality") or None,
            organization=cfg.get("subject_org") or None,
            organizational_unit=cfg.get("subject_ou") or None,
        )
        ku  = KeyUsageDefaults(
            digital_signature=self.chk_dig_sig.isChecked(),
            key_encipherment=self.chk_key_enc.isChecked(),
        )
        eku = EkuDefaults(
            server_auth=self.chk_srv_auth.isChecked(),
            client_auth=self.chk_cli_auth.isChecked(),
        )
        try:
            save_template(name, subject, ku, eku, int(self.combo_key_size.currentText()))
        except CertToolError as e:
            self.log_emitter.message.emit(f"Failed to save template: {e}", "CSR")
            return
        self.log_emitter.message.emit(f"Template '{name}' saved.", "CSR")
        self.edit_tpl_name.clear()
        self._refresh_templates()

    # ------------------------------------------------------------------
    # SAN slots
    # ------------------------------------------------------------------

    def _add_san(self) -> None:
        raw = self.edit_san_entry.text().strip()
        if not raw:
            return
        added = 0
        for entry in parse_user_sans(raw):
            if entry not in self._sans:
                self._sans.append(entry)
                added += 1
        self.edit_san_entry.clear()
        self._refresh_san_list()
        if not added:
            self.log_emitter.message.emit(
                "SAN already in list or not a valid hostname/IP.", "CSR"
            )

    def _seed_sans(self) -> None:
        cn = self.edit_cn.text().strip().lower()
        if not cn:
            self.log_emitter.message.emit("Enter a Common Name first.", "CSR")
            return
        self._sans.clear()
        self._sans.append(SanEntry(SanType.DNS, cn))
        self._sans.append(SanEntry(SanType.DNS, f"www.{cn}"))
        self._refresh_san_list()

    def _remove_san(self) -> None:
        for item in reversed(self.san_list.selectedItems()):
            row = self.san_list.row(item)
            if 0 <= row < len(self._sans):
                self._sans.pop(row)
        self._refresh_san_list()

    # ------------------------------------------------------------------
    # Output / generate slots
    # ------------------------------------------------------------------

    def _browse_output(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self.edit_out_dir.setText(folder)

    def _generate(self) -> None:
        cn = self.edit_cn.text().strip()
        if not cn:
            self.log_emitter.message.emit("Common Name is required.", "CSR")
            return

        out_dir = self.edit_out_dir.text().strip()
        if not out_dir:
            self.log_emitter.message.emit("Output directory is required.", "CSR")
            return

        password: Optional[str] = None
        if self.chk_encrypt_key.isChecked():
            pw = self.edit_password.text()
            if not pw:
                self.log_emitter.message.emit(
                    "Password cannot be empty when key encryption is enabled.", "CSR"
                )
                return
            password = pw

        cfg = load_app_config()
        spec = CsrSpec(
            common_name=cn,
            sans=list(self._sans),
            subject_defaults=SubjectDefaults(
                country=cfg.get("subject_country") or None,
                state=cfg.get("subject_state") or None,
                locality=cfg.get("subject_locality") or None,
                organization=cfg.get("subject_org") or None,
                organizational_unit=cfg.get("subject_ou") or None,
            ),
            key_usage=KeyUsageDefaults(
                digital_signature=self.chk_dig_sig.isChecked(),
                key_encipherment=self.chk_key_enc.isChecked(),
            ),
            eku=EkuDefaults(
                server_auth=self.chk_srv_auth.isChecked(),
                client_auth=self.chk_cli_auth.isChecked(),
            ),
            key_size=int(self.combo_key_size.currentText()),
        )

        try:
            result = generate_csr_and_keys(spec, out_dir, key_password=password)
        except CertToolError as e:
            self.log_emitter.message.emit(f"Generation failed: {e}", "CSR")
            return

        self.log_emitter.message.emit(f"CSR:          {result.csr_pem}", "CSR")
        self.log_emitter.message.emit(f"Key:          {result.key_unencrypted}", "CSR")
        if result.key_encrypted:
            self.log_emitter.message.emit(
                f"Key (enc):    {result.key_encrypted}", "CSR"
            )
        if result.csr_der:
            self.log_emitter.message.emit(f"CSR (DER):    {result.csr_der}", "CSR")
