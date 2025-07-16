import os
import hashlib
from datetime import date
from tkinter import Tk, filedialog, scrolledtext, Button, Label, Entry, Listbox, Toplevel, messagebox
from cryptography import x509 # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore

LOG_FOLDER = r"C:\Certs\logs"
os.makedirs(LOG_FOLDER, exist_ok=True)

# ---------- Core Cert/Key/CSR Verification Logic ----------

def get_modulus(obj):
    try:
        if isinstance(obj, (x509.Certificate, x509.CertificateSigningRequest)):
            return obj.public_key().public_numbers().n
        elif isinstance(obj, rsa.RSAPrivateKey):
            return obj.private_numbers().public_numbers.n
    except Exception:
        return None
    return None

def load_pem_file(path):
    with open(path, 'rb') as f:
        data = f.read()

    try:
        if b'PRIVATE KEY' in data:
            try:
                key = serialization.load_pem_private_key(data, password=None, backend=default_backend())
                return key, 'key', False
            except TypeError:
                return None, 'key', True
        elif b'CERTIFICATE REQUEST' in data:
            return x509.load_pem_x509_csr(data, default_backend()), 'csr', False
        elif b'CERTIFICATE' in data:
            return x509.load_pem_x509_certificate(data, default_backend()), 'cert', False
    except Exception:
        return None, None, False
    return None, None, False

def find_files(folder):
    return [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(('.key', '.crt', '.cer', '.csr', '.req', '.pem'))
    ]

def check_folder(folder):
    log_lines = []
    log_lines.append(f"Checking: {folder}")
    result = {"key": None, "cert": None, "csr": None}
    protection = {"key": None}
    files = find_files(folder)

    for file in files:
        obj, kind, is_protected = load_pem_file(file)
        if kind and result[kind] is None:
            if obj:
                result[kind] = (file, get_modulus(obj))
            if kind == 'key':
                protection['key'] = is_protected

    found = {k: v for k, v in result.items() if v is not None}

    if len(found) < 2:
        log_lines.append(f"⚠️ Not enough valid files found in {folder}")
        return "\n".join(log_lines)

    moduli = [v[1] for v in found.values()]
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
            hash = hashlib.md5(str(m).encode()).hexdigest()
            log_lines.append(f"   {k.upper()}: {os.path.basename(file)} [mod hash: {hash}]")

    return "\n".join(log_lines)

def run_check():
    folder = filedialog.askdirectory(title="Select Folder with Certs/Keys")
    if not folder:
        return
    output = check_folder(folder)
    output_box.delete('1.0', 'end')
    output_box.insert('end', output)

    # Log to daily file
    today_str = date.today().strftime("%Y-%m-%d")
    logfile = os.path.join(LOG_FOLDER, f"cert_check_{today_str}.txt")

    try:
        with open(logfile, 'a', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write(f"📁 Folder Checked: {folder}\n")
            f.write(output + "\n\n")
    except UnicodeEncodeError:
        with open(logfile, 'a', encoding='utf-8', errors='replace') as f:
            f.write("="*60 + "\n")
            f.write(f"Folder Checked: {folder}\n")
            f.write(output + "\n\n")

    output_box.insert('end', f"\n\n📁 Appended results to: {logfile}")

# ---------- SAN String Generator from CSR ----------

def extract_common_name_from_csr(csr_path):
    with open(csr_path, 'rb') as f:
        data = f.read()
    csr = x509.load_pem_x509_csr(data, default_backend())
    cn = None
    for attr in csr.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            cn = attr.value
            break
    return cn

class SANGeneratorApp(Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("SAN String Generator")
        self.geometry("600x400")
        self.resizable(False, False)

        self.san_list = []

        Button(self, text="Load CSR", command=self.load_csr).pack(pady=5)
        self.cn_label = Label(self, text="Common Name: ")
        self.cn_label.pack()

        self.san_entry = Entry(self, width=50)
        self.san_entry.pack(pady=5)
        Button(self, text="Add SAN", command=self.add_san).pack()

        self.san_box = Listbox(self, width=70, height=10)
        self.san_box.pack(pady=5)

        Button(self, text="Remove Selected", command=self.remove_selected).pack()

        Label(self, text="Output (for MS PKI):").pack(pady=5)
        self.output_field = Entry(self, width=80)
        self.output_field.pack(pady=5)

        Button(self, text="Generate SAN String", command=self.generate_output).pack(pady=5)

    def load_csr(self):
        path = filedialog.askopenfilename(title="Select CSR", filetypes=[("CSR files", "*.csr *.req *.pem")])
        if not path:
            return
        try:
            cn = extract_common_name_from_csr(path)
            if not cn:
                raise ValueError("No CN found.")
            self.cn_label.config(text=f"Common Name: {cn}")
            self.san_list = [cn, f"www.{cn}"]
            self.refresh_san_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSR: {str(e)}")

    def refresh_san_list(self):
        self.san_box.delete(0, 'end')
        for san in self.san_list:
            self.san_box.insert('end', san)

    def add_san(self):
        value = self.san_entry.get().strip()
        if value and value not in self.san_list:
            self.san_list.append(value)
            self.refresh_san_list()
        self.san_entry.delete(0, 'end')

    def remove_selected(self):
        selection = self.san_box.curselection()
        for index in reversed(selection):
            self.san_list.pop(index)
        self.refresh_san_list()

    def generate_output(self):
        san_string = "san:" + "&".join([f"dns={san}" for san in self.san_list])
        self.output_field.delete(0, 'end')
        self.output_field.insert(0, san_string)

# ---------- Main GUI ----------

root = Tk()
root.title("Certificate Tool")
root.geometry("700x550")

Label(root, text="Certificate Set Verifier").pack(pady=10)
Button(root, text="Verify Cert/Key/CSR Set", command=run_check).pack(pady=5)
Button(root, text="Generate SAN from CSR", command=lambda: SANGeneratorApp(root)).pack(pady=5)

output_box = scrolledtext.ScrolledText(root, wrap='word', font=("Consolas", 10))
output_box.pack(fill='both', expand=True, padx=10, pady=10)

root.mainloop()
