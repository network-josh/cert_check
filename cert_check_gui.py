import os
import hashlib
import json
import csv
from datetime import date
from tkinter import (
    Tk, Frame, StringVar, BooleanVar,
    filedialog, messagebox
)
from tkinter.scrolledtext import ScrolledText
from tkinter import simpledialog
from tkinter import ttk

from cryptography import x509  # type: ignore
from cryptography.hazmat.primitives import serialization, hashes  # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID  # type: ignore

LOG_FOLDER = r"C:\Certs\logs"
CONFIG_PATH = r"C:\Certs\cert_tool_config.json"

os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

DEFAULT_CONFIG = {
    "country": "US",
    "state": "Kentucky",
    "locality": "Lexington",
    "organization": "",
    "organizational_unit": "",
    "default_key_size": 2048,
    "ku_digital_signature": True,
    "ku_key_encipherment": True,
    "eku_server_auth": True,
    "eku_client_auth": False
}


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    else:
        data = {}
    cfg = DEFAULT_CONFIG.copy()
    cfg.update({k: v for k, v in data.items() if k in cfg})
    return cfg


def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


class CertToolApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("Certificate Tool")
        self.root.geometry("900x650")

        self.config = load_config()

        # State for various tabs
        self.leaf_cert = None  # for Chain Helper
        self.leaf_cert_path = None

        # CSR tab state
        self.csr_mode = StringVar(value="single")
        self.csr_output_dir = StringVar(value=os.getcwd())
        self.csr_key_size = StringVar(value=str(self.config["default_key_size"]))
        self.csr_key_password = StringVar(value="")
        self.csr_include_default_sans = BooleanVar(value=True)
        self.csr_export_der = BooleanVar(value=False)

        # Settings tab variables
        self.var_country = StringVar(value=self.config["country"])
        self.var_state = StringVar(value=self.config["state"])
        self.var_locality = StringVar(value=self.config["locality"])
        self.var_org = StringVar(value=self.config["organization"])
        self.var_ou = StringVar(value=self.config["organizational_unit"])
        self.var_ku_dsig = BooleanVar(value=self.config["ku_digital_signature"])
        self.var_ku_kenc = BooleanVar(value=self.config["ku_key_encipherment"])
        self.var_eku_server = BooleanVar(value=self.config["eku_server_auth"])
        self.var_eku_client = BooleanVar(value=self.config["eku_client_auth"])

        self._build_ui()

    # ---------- Generic crypto helpers ----------

    def get_modulus(self, obj):
        try:
            if isinstance(obj, (x509.Certificate, x509.CertificateSigningRequest)):
                return obj.public_key().public_numbers().n
            elif isinstance(obj, rsa.RSAPrivateKey):
                return obj.private_numbers().public_numbers.n
        except Exception:
            return None
        return None

    def load_pem_file_with_password_prompt(self, path):
        """
        Try to load PEM as key/cert/CSR. Prompt for password if key is encrypted.
        Returns (obj, kind, is_password_protected)
        kind: 'key', 'cert', 'csr', or None
        """
        with open(path, 'rb') as f:
            data = f.read()

        try:
            if b'PRIVATE KEY' in data:
                # First try no password
                try:
                    key = serialization.load_pem_private_key(
                        data, password=None, backend=default_backend()
                    )
                    return key, 'key', False
                except TypeError:
                    # password required
                    pw = simpledialog.askstring(
                        "Password Required",
                        f"Enter password for key file:\n{os.path.basename(path)}",
                        show="*",
                        parent=self.root
                    )
                    if not pw:
                        # user cancelled or empty
                        return None, 'key', True
                    try:
                        key = serialization.load_pem_private_key(
                            data, password=pw.encode('utf-8'),
                            backend=default_backend()
                        )
                        return key, 'key', True
                    except Exception:
                        messagebox.showerror(
                            "Error",
                            f"Unable to decrypt key file:\n{os.path.basename(path)}"
                        )
                        return None, 'key', True

            elif b'CERTIFICATE REQUEST' in data:
                return x509.load_pem_x509_csr(data, default_backend()), 'csr', False
            elif b'CERTIFICATE' in data:
                return x509.load_pem_x509_certificate(data, default_backend()), 'cert', False
        except Exception:
            return None, None, False

        return None, None, False

    # ---------- UI construction ----------

    def _build_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        self.tab_verify = Frame(notebook)
        self.tab_san = Frame(notebook)
        self.tab_csr = Frame(notebook)
        self.tab_chain = Frame(notebook)
        self.tab_settings = Frame(notebook)

        notebook.add(self.tab_verify, text="Verify Set")
        notebook.add(self.tab_san, text="SAN from CSR")
        notebook.add(self.tab_csr, text="Create CSR")
        notebook.add(self.tab_chain, text="Chain Helper")
        notebook.add(self.tab_settings, text="Settings")

        self._build_verify_tab()
        self._build_san_tab()
        self._build_csr_tab()
        self._build_chain_tab()
        self._build_settings_tab()

    # ---------- Verify Set tab ----------

    def _build_verify_tab(self):
        top_frame = Frame(self.tab_verify)
        top_frame.pack(fill="x", pady=5)

        btn = ttk.Button(top_frame, text="Select Folder and Verify", command=self.run_check)
        btn.pack(side="left", padx=5)

        self.verify_output = ScrolledText(
            self.tab_verify, wrap="word", font=("Consolas", 10)
        )
        self.verify_output.pack(fill="both", expand=True, padx=10, pady=10)

    def find_files(self, folder):
        return [
            os.path.join(folder, f)
            for f in os.listdir(folder)
            if os.path.isfile(os.path.join(folder, f)) and
               f.lower().endswith(('.key', '.crt', '.cer', '.csr', '.req', '.pem'))
        ]

    def check_folder(self, folder):
        log_lines = []
        log_lines.append(f"Checking: {folder}")
        result = {"key": None, "cert": None, "csr": None}
        protection = {"key": None}
        files = self.find_files(folder)

        for file in files:
            obj, kind, is_protected = self.load_pem_file_with_password_prompt(file)
            if kind and result.get(kind) is None:
                if obj:
                    result[kind] = (file, self.get_modulus(obj))
                if kind == 'key':
                    protection['key'] = is_protected

        found = {k: v for k, v in result.items() if v is not None}

        if len(found) < 2:
            log_lines.append(f"⚠️ Not enough valid files found in {folder}")
            return "\n".join(log_lines)

        moduli = [v[1] for v in found.values()]
        if None in moduli:
            log_lines.append("⚠️ One or more items did not have a valid modulus.")
            return "\n".join(log_lines)

        if len(set(moduli)) == 1:
            log_lines.append("✅ All components match:")
            for k, (file, _) in found.items():
                log_lines.append(f"   {k.upper()}: {os.path.basename(file)}")
            if protection['key']:
                log_lines.append("   🔐 Private key is password protected.")
            else:
                log_lines.append("   🔓 Private key is NOT password protected.")
        else:
            log_lines.append("❌ Mismatch detected:")
            for k, (file, m) in found.items():
                hash_hex = hashlib.md5(str(m).encode()).hexdigest()
                log_lines.append(f"   {k.upper()}: {os.path.basename(file)} [mod hash: {hash_hex}]")

        return "\n".join(log_lines)

    def run_check(self):
        folder = filedialog.askdirectory(title="Select Folder with Certs/Keys", parent=self.root)
        if not folder:
            return
        output = self.check_folder(folder)
        self.verify_output.delete("1.0", "end")
        self.verify_output.insert("end", output)

        # Log to daily file
        today_str = date.today().strftime("%Y-%m-%d")
        logfile = os.path.join(LOG_FOLDER, f"cert_check_{today_str}.txt")

        try:
            with open(logfile, 'a', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write(f"📁 Folder Checked: {folder}\n")
                f.write(output + "\n\n")
        except UnicodeEncodeError:
            with open(logfile, 'a', encoding='utf-8', errors='replace') as f:
                f.write("=" * 60 + "\n")
                f.write(f"Folder Checked: {folder}\n")
                f.write(output + "\n\n")

        self.verify_output.insert("end", f"\n\n📁 Appended results to: {logfile}")

    # ---------- SAN from CSR tab ----------

    def _build_san_tab(self):
        top = Frame(self.tab_san)
        top.pack(fill="x", pady=5)

        btn_load = ttk.Button(top, text="Load CSR", command=self.san_load_csr)
        btn_load.pack(side="left", padx=5)

        self.san_cn_label = ttk.Label(top, text="Common Name: (none)")
        self.san_cn_label.pack(side="left", padx=10)

        mid = Frame(self.tab_san)
        mid.pack(fill="x", pady=5)

        ttk.Label(mid, text="Add SAN (hostname):").pack(side="left", padx=5)
        self.san_entry = ttk.Entry(mid, width=40)
        self.san_entry.pack(side="left", padx=5)
        ttk.Button(mid, text="Add SAN", command=self.san_add_san).pack(side="left", padx=5)

        list_frame = Frame(self.tab_san)
        list_frame.pack(fill="both", expand=False, pady=5)
        self.san_list = []
        self.san_listbox = ttk.Listbox(list_frame, height=8)
        self.san_listbox.pack(side="left", fill="both", expand=True, padx=10)
        ttk.Button(list_frame, text="Remove Selected", command=self.san_remove_selected).pack(
            side="left", padx=5
        )

        out_frame = Frame(self.tab_san)
        out_frame.pack(fill="x", pady=10)
        ttk.Label(out_frame, text="Output (for MS PKI):").pack(anchor="w", padx=10)
        self.san_output_entry = ttk.Entry(out_frame, width=80)
        self.san_output_entry.pack(anchor="w", padx=10, pady=5)

        bottom = Frame(self.tab_san)
        bottom.pack(fill="x", pady=5)
        ttk.Button(bottom, text="Generate SAN String", command=self.san_generate_output).pack(
            side="left", padx=10
        )
        ttk.Button(bottom, text="Copy to Clipboard", command=self.san_copy_clipboard).pack(
            side="left", padx=5
        )

    def san_load_csr(self):
        path = filedialog.askopenfilename(
            title="Select CSR",
            filetypes=[("CSR files", "*.csr *.req *.pem *.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            csr = x509.load_pem_x509_csr(data, default_backend())
            cn = None
            for attr in csr.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    cn = attr.value
                    break
            if not cn:
                raise ValueError("No Common Name found in CSR.")
            self.san_cn_label.config(text=f"Common Name: {cn}")
            self.san_list = [cn, f"www.{cn}"]
            self.san_refresh_listbox()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSR: {e}")

    def san_refresh_listbox(self):
        self.san_listbox.delete(0, "end")
        for san in self.san_list:
            self.san_listbox.insert("end", san)

    def san_add_san(self):
        value = self.san_entry.get().strip()
        if value and value not in self.san_list:
            self.san_list.append(value)
            self.san_refresh_listbox()
        self.san_entry.delete(0, "end")

    def san_remove_selected(self):
        selection = list(self.san_listbox.curselection())
        selection.reverse()
        for idx in selection:
            self.san_list.pop(idx)
        self.san_refresh_listbox()

    def san_generate_output(self):
        san_string = "san:" + "&".join([f"dns={san}" for san in self.san_list])
        self.san_output_entry.delete(0, "end")
        self.san_output_entry.insert(0, san_string)

    def san_copy_clipboard(self):
        text = self.san_output_entry.get()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            messagebox.showinfo("Copied", "SAN string copied to clipboard.")

    # ---------- Create CSR tab ----------

    def _build_csr_tab(self):
        # Mode selection
        mode_frame = Frame(self.tab_csr)
        mode_frame.pack(fill="x", pady=5)

        ttk.Label(mode_frame, text="Mode:").pack(side="left", padx=5)
        ttk.Radiobutton(
            mode_frame, text="Single CSR", variable=self.csr_mode, value="single",
            command=self.update_csr_mode
        ).pack(side="left", padx=5)
        ttk.Radiobutton(
            mode_frame, text="CSV Batch", variable=self.csr_mode, value="csv",
            command=self.update_csr_mode
        ).pack(side="left", padx=5)

        # Key options + output folder
        opt_frame = Frame(self.tab_csr)
        opt_frame.pack(fill="x", pady=5)

        ttk.Label(opt_frame, text="Key Size:").pack(side="left", padx=5)
        self.csr_keysize_combo = ttk.Combobox(
            opt_frame, textvariable=self.csr_key_size,
            values=["2048", "3072", "4096"], width=8, state="readonly"
        )
        self.csr_keysize_combo.pack(side="left", padx=5)

        ttk.Label(opt_frame, text="Key Password (for encrypted .enc.key):").pack(
            side="left", padx=10
        )
        self.csr_key_pwd_entry = ttk.Entry(opt_frame, textvariable=self.csr_key_password, show="*", width=20)
        self.csr_key_pwd_entry.pack(side="left", padx=5)

        ttk.Checkbutton(
            opt_frame, text="Also export CSR as DER (.csr.der)",
            variable=self.csr_export_der
        ).pack(side="left", padx=10)

        folder_frame = Frame(self.tab_csr)
        folder_frame.pack(fill="x", pady=5)
        ttk.Label(folder_frame, text="Output Folder:").pack(side="left", padx=5)
        self.csr_output_entry = ttk.Entry(folder_frame, textvariable=self.csr_output_dir, width=50)
        self.csr_output_entry.pack(side="left", padx=5)
        ttk.Button(folder_frame, text="Browse...", command=self.browse_csr_output_folder).pack(
            side="left", padx=5
        )

        # Single mode frame
        self.csr_single_frame = Frame(self.tab_csr)
        self.csr_single_frame.pack(fill="x", pady=10)

        ttk.Label(self.csr_single_frame, text="Common Name (CN):").pack(anchor="w", padx=10)
        self.csr_single_cn_entry = ttk.Entry(self.csr_single_frame, width=50)
        self.csr_single_cn_entry.pack(anchor="w", padx=10, pady=2)

        ttk.Label(self.csr_single_frame, text="Additional SANs (separated by ; or ,):").pack(
            anchor="w", padx=10
        )
        self.csr_single_sans_entry = ttk.Entry(self.csr_single_frame, width=70)
        self.csr_single_sans_entry.pack(anchor="w", padx=10, pady=2)

        ttk.Checkbutton(
            self.csr_single_frame,
            text="Include CN and www.CN automatically",
            variable=self.csr_include_default_sans
        ).pack(anchor="w", padx=10, pady=2)

        ttk.Button(
            self.csr_single_frame, text="Generate CSR",
            command=self.generate_single_csr
        ).pack(anchor="w", padx=10, pady=5)

        # CSV mode frame
        self.csr_csv_frame = Frame(self.tab_csr)

        ttk.Label(self.csr_csv_frame, text="CSV file (with at least CN column, optional SANs):").pack(
            anchor="w", padx=10, pady=2
        )
        csv_sel_frame = Frame(self.csr_csv_frame)
        csv_sel_frame.pack(fill="x", pady=2)
        self.csr_csv_path_var = StringVar(value="")
        self.csr_csv_entry = ttk.Entry(csv_sel_frame, textvariable=self.csr_csv_path_var, width=50)
        self.csr_csv_entry.pack(side="left", padx=10)
        ttk.Button(csv_sel_frame, text="Browse...", command=self.browse_csr_csv).pack(
            side="left", padx=5
        )

        ttk.Button(
            self.csr_csv_frame, text="Generate CSRs from CSV",
            command=self.generate_csrs_from_csv
        ).pack(anchor="w", padx=10, pady=5)

        # Output log
        self.csr_output_log = ScrolledText(
            self.tab_csr, wrap="word", font=("Consolas", 10), height=12
        )
        self.csr_output_log.pack(fill="both", expand=True, padx=10, pady=10)

        self.update_csr_mode()

    def update_csr_mode(self):
        if self.csr_mode.get() == "single":
            self.csr_csv_frame.pack_forget()
            self.csr_single_frame.pack(fill="x", pady=10)
        else:
            self.csr_single_frame.pack_forget()
            self.csr_csv_frame.pack(fill="x", pady=10)

    def browse_csr_output_folder(self):
        folder = filedialog.askdirectory(title="Select Output Folder", parent=self.root)
        if folder:
            self.csr_output_dir.set(folder)

    def browse_csr_csv(self):
        path = filedialog.askopenfilename(
            title="Select CSV",
            filetypes=[("CSV file", "*.csv"), ("All files", "*.*")]
        )
        if path:
            self.csr_csv_path_var.set(path)

    def generate_single_csr(self):
        cn = self.csr_single_cn_entry.get().strip()
        if not cn:
            messagebox.showerror("Error", "Common Name (CN) is required.")
            return
        sans_raw = self.csr_single_sans_entry.get().strip()
        sans_list = self.parse_sans(sans_raw)

        if self.csr_include_default_sans.get():
            if cn not in sans_list:
                sans_list.insert(0, cn)
            www_cn = f"www.{cn}"
            if www_cn not in sans_list:
                sans_list.insert(1, www_cn)

        result = self.generate_csr_and_keys_for_entry(cn, sans_list)
        self.csr_output_log.insert("end", result + "\n")
        self.csr_output_log.see("end")

    def generate_csrs_from_csv(self):
        path = self.csr_csv_path_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "CSV file not found.")
            return

        results = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if "CN" not in reader.fieldnames and "cn" not in reader.fieldnames:
                messagebox.showerror("Error", "CSV must contain a CN column.")
                return
            for row in reader:
                cn = row.get("CN") or row.get("cn") or ""
                cn = cn.strip()
                if not cn:
                    continue
                san_field = row.get("SANs") or row.get("sans") or ""
                sans_list = self.parse_sans(san_field)
                if not sans_list and self.csr_include_default_sans.get():
                    sans_list = [cn, f"www.{cn}"]
                elif self.csr_include_default_sans.get():
                    if cn not in sans_list:
                        sans_list.insert(0, cn)
                    www_cn = f"www.{cn}"
                    if www_cn not in sans_list:
                        sans_list.insert(1, www_cn)
                results.append(self.generate_csr_and_keys_for_entry(cn, sans_list))

        self.csr_output_log.insert("end", "\n".join(results) + "\n")
        self.csr_output_log.see("end")

    def parse_sans(self, text):
        if not text:
            return []
        parts = [p.strip() for p in text.replace(",", ";").split(";")]
        return [p for p in parts if p]

    def generate_csr_and_keys_for_entry(self, cn, sans_list):
        out_dir = self.csr_output_dir.get().strip() or os.getcwd()
        os.makedirs(out_dir, exist_ok=True)

        try:
            key_size = int(self.csr_key_size.get())
        except ValueError:
            key_size = 2048

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # Subject
        name_attrs = []
        if self.var_country.get():
            name_attrs.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.var_country.get()))
        if self.var_state.get():
            name_attrs.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.var_state.get()))
        if self.var_locality.get():
            name_attrs.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.var_locality.get()))
        if self.var_org.get():
            name_attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.var_org.get()))
        if self.var_ou.get():
            name_attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.var_ou.get()))
        name_attrs.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, cn))

        subject = x509.Name(name_attrs)

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        if sans_list:
            san_objs = [x509.DNSName(s) for s in sans_list]
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_objs),
                critical=False
            )

        # Key Usage
        ku = x509.KeyUsage(
            digital_signature=self.var_ku_dsig.get(),
            key_encipherment=self.var_ku_kenc.get(),
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )
        csr_builder = csr_builder.add_extension(ku, critical=True)

        # EKU
        eku_oids = []
        if self.var_eku_server.get():
            eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if self.var_eku_client.get():
            eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        if eku_oids:
            csr_builder = csr_builder.add_extension(
                x509.ExtendedKeyUsage(eku_oids),
                critical=False
            )

        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        # Save files
        safe_cn = "".join(c if c.isalnum() or c in "._-" else "_" for c in cn)
        key_path = os.path.join(out_dir, f"{safe_cn}.key")
        enc_key_path = os.path.join(out_dir, f"{safe_cn}.enc.key")
        csr_pem_path = os.path.join(out_dir, f"{safe_cn}.csr")

        # Unencrypted key
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Encrypted key (optional)
        pwd = self.csr_key_password.get()
        if pwd:
            with open(enc_key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.BestAvailableEncryption(pwd.encode("utf-8"))
                    )
                )

        # CSR PEM
        with open(csr_pem_path, "wb") as f:
            f.write(
                csr.public_bytes(serialization.Encoding.PEM)
            )

        # Optional CSR DER
        if self.csr_export_der.get():
            csr_der_path = os.path.join(out_dir, f"{safe_cn}.csr.der")
            with open(csr_der_path, "wb") as f:
                f.write(
                    csr.public_bytes(serialization.Encoding.DER)
                )
        else:
            csr_der_path = None

        msg = f"Generated CSR/key for CN={cn} in {out_dir}"
        if csr_der_path:
            msg += " (PEM + DER)"
        return msg

    # ---------- Chain Helper tab ----------

    def _build_chain_tab(self):
        top = Frame(self.tab_chain)
        top.pack(fill="x", pady=5)

        ttk.Button(top, text="Load Leaf Certificate", command=self.chain_load_leaf_cert).pack(
            side="left", padx=5
        )

        self.chain_leaf_subject_label = ttk.Label(top, text="Leaf Subject: (none)")
        self.chain_leaf_subject_label.pack(side="left", padx=10)

        self.chain_leaf_issuer_label = ttk.Label(top, text="Leaf Issuer: (none)")
        self.chain_leaf_issuer_label.pack(side="left", padx=10)

        mid = Frame(self.tab_chain)
        mid.pack(fill="x", pady=5)

        ttk.Button(
            mid, text="Select Chain Folder", command=self.chain_select_folder
        ).pack(side="left", padx=5)

        self.chain_results = ScrolledText(
            self.tab_chain, wrap="word", font=("Consolas", 10)
        )
        self.chain_results.pack(fill="both", expand=True, padx=10, pady=10)

    def chain_load_leaf_cert(self):
        path = filedialog.askopenfilename(
            title="Select Leaf Certificate",
            filetypes=[("Certificate files", "*.crt *.cer *.pem *.der"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            if b"BEGIN CERTIFICATE" in data:
                cert = x509.load_pem_x509_certificate(data, default_backend())
            else:
                cert = x509.load_der_x509_certificate(data, default_backend())

            self.leaf_cert = cert
            self.leaf_cert_path = path

            subj = cert.subject.rfc4514_string()
            iss = cert.issuer.rfc4514_string()

            self.chain_leaf_subject_label.config(text=f"Leaf Subject: {subj}")
            self.chain_leaf_issuer_label.config(text=f"Leaf Issuer: {iss}")

            self.chain_results.delete("1.0", "end")
            self.chain_results.insert("end", f"Loaded leaf certificate: {os.path.basename(path)}\n")
            self.chain_results.insert("end", f"Subject: {subj}\n")
            self.chain_results.insert("end", f"Issuer : {iss}\n\n")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load certificate: {e}")

    def chain_select_folder(self):
        if not self.leaf_cert:
            messagebox.showerror("Error", "Load a leaf certificate first.")
            return

        folder = filedialog.askdirectory(title="Select Folder with Chain Certs", parent=self.root)
        if not folder:
            return

        self.chain_results.insert("end", f"Scanning folder: {folder}\n\n")
        self.chain_results.see("end")

        leaf_issuer = self.leaf_cert.issuer.rfc4514_string()
        leaf_aki = None
        try:
            aki_ext = self.leaf_cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
            leaf_aki = aki_ext.value.key_identifier
        except x509.ExtensionNotFound:
            leaf_aki = None

        for fname in os.listdir(folder):
            full = os.path.join(folder, fname)
            if not os.path.isfile(full):
                continue
            if not fname.lower().endswith((".crt", ".cer", ".pem", ".der")):
                continue

            try:
                with open(full, "rb") as f:
                    data = f.read()
                if b"BEGIN CERTIFICATE" in data:
                    cert = x509.load_pem_x509_certificate(data, default_backend())
                else:
                    cert = x509.load_der_x509_certificate(data, default_backend())
            except Exception:
                continue

            subj = cert.subject.rfc4514_string()
            iss = cert.issuer.rfc4514_string()
            fingerprint = cert.fingerprint(hashes.SHA1()).hex()

            ski = None
            try:
                ski_ext = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER
                )
                ski = ski_ext.value.digest
            except x509.ExtensionNotFound:
                ski = None

            likely = False
            reason = []
            if subj == leaf_issuer:
                likely = True
                reason.append("subject == leaf issuer")

            if leaf_aki is not None and ski is not None and leaf_aki == ski:
                likely = True
                reason.append("AKI matches SKI")

            tag = "[LIKELY MATCH]" if likely else "[candidate]"

            self.chain_results.insert(
                "end",
                f"{tag} {fname}\n"
                f"  Subject: {subj}\n"
                f"  Issuer : {iss}\n"
                f"  SHA1   : {fingerprint}\n"
            )
            if reason:
                self.chain_results.insert("end", f"  Reason : {', '.join(reason)}\n")
            self.chain_results.insert("end", "\n")
            self.chain_results.see("end")

    # ---------- Settings tab ----------

    def _build_settings_tab(self):
        frame = Frame(self.tab_settings)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Org data
        org_frame = ttk.LabelFrame(frame, text="Subject Defaults")
        org_frame.pack(fill="x", pady=5)

        ttk.Label(org_frame, text="Country (C):").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(org_frame, textvariable=self.var_country, width=10).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(org_frame, text="State/Province (ST):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(org_frame, textvariable=self.var_state, width=20).grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(org_frame, text="Locality/City (L):").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(org_frame, textvariable=self.var_locality, width=20).grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(org_frame, text="Organization (O):").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(org_frame, textvariable=self.var_org, width=40).grid(row=3, column=1, padx=5, pady=2)

        ttk.Label(org_frame, text="Org Unit (OU):").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(org_frame, textvariable=self.var_ou, width=40).grid(row=4, column=1, padx=5, pady=2)

        # Key defaults
        key_frame = ttk.LabelFrame(frame, text="Key / Usage Defaults")
        key_frame.pack(fill="x", pady=5)

        ttk.Label(key_frame, text="Default Key Size:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.settings_keysize_combo = ttk.Combobox(
            key_frame,
            values=["2048", "3072", "4096"],
            width=8
        )
        self.settings_keysize_combo.set(str(self.config["default_key_size"]))
        self.settings_keysize_combo.grid(row=0, column=1, padx=5, pady=2)

        ttk.Checkbutton(
            key_frame, text="Key Usage: Digital Signature",
            variable=self.var_ku_dsig
        ).grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        ttk.Checkbutton(
            key_frame, text="Key Usage: Key Encipherment",
            variable=self.var_ku_kenc
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        ttk.Checkbutton(
            key_frame, text="EKU: Server Authentication",
            variable=self.var_eku_server
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        ttk.Checkbutton(
            key_frame, text="EKU: Client Authentication",
            variable=self.var_eku_client
        ).grid(row=4, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        # Save button
        ttk.Button(frame, text="Save Settings", command=self.save_settings).pack(
            anchor="w", pady=10
        )

    def save_settings(self):
        try:
            key_size = int(self.settings_keysize_combo.get())
        except ValueError:
            key_size = 2048

        self.config["country"] = self.var_country.get()
        self.config["state"] = self.var_state.get()
        self.config["locality"] = self.var_locality.get()
        self.config["organization"] = self.var_org.get()
        self.config["organizational_unit"] = self.var_ou.get()
        self.config["default_key_size"] = key_size
        self.config["ku_digital_signature"] = self.var_ku_dsig.get()
        self.config["ku_key_encipherment"] = self.var_ku_kenc.get()
        self.config["eku_server_auth"] = self.var_eku_server.get()
        self.config["eku_client_auth"] = self.var_eku_client.get()

        save_config(self.config)
        self.csr_key_size.set(str(self.config["default_key_size"]))
        self.settings_keysize_combo.set(str(self.config["default_key_size"]))
        messagebox.showinfo("Settings", "Settings saved.")


if __name__ == "__main__":
    root = Tk()
    app = CertToolApp(root)
    root.mainloop()
