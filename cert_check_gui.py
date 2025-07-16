import os
import hashlib
from datetime import date
from datetime import datetime
from tkinter import Tk, filedialog, scrolledtext, Button, Label
from getpass import getpass
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

LOG_FOLDER = r"C:\Certs\logs"
os.makedirs(LOG_FOLDER, exist_ok=True)


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
    """Try to load the file and identify the type (key, cert, or csr)"""
    with open(path, 'rb') as f:
        data = f.read()

    try:
        if b'PRIVATE KEY' in data:
            try:
                key = serialization.load_pem_private_key(data, password=None, backend=default_backend())
                return key, 'key', False
            except TypeError:
                # Password protected key
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
        line = f"⚠️ Not enough valid files found in {folder}"
        log_lines.append(line)
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

    '''
    # Save log
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = os.path.join(LOG_FOLDER, f"cert_check_{timestamp}.txt")
    with open(logfile, 'a', encoding='utf-8') as f:
        f.write(output + "\n")
    output_box.insert('end', f"\n\n📁 Log saved to: {logfile}")
    '''

    # Save log (one file per day)
    today_str = date.today().strftime("%Y-%m-%d")
    logfile = os.path.join(LOG_FOLDER, f"cert_check_{today_str}.txt")

    with open(logfile, 'a', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write(f"📁 Folder Checked: {folder}\n")
        f.write(output + "\n\n")
    output_box.insert('end', f"\n\n📁 Appended results to: {logfile}")

# --- GUI ---
root = Tk()
root.title("Certificate Set Verifier")
root.geometry("700x500")

Label(root, text="Cert/Key/CSR Matching Tool").pack(pady=10)

Button(root, text="Select Folder and Run Check", command=run_check).pack(pady=5)

output_box = scrolledtext.ScrolledText(root, wrap='word', font=("Consolas", 10))
output_box.pack(fill='both', expand=True, padx=10, pady=10)

root.mainloop()
