import os
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_pem_file(path, password=None):
    with open(path, 'rb') as f:
        data = f.read()

    try:
        if b'PRIVATE KEY' in data:
            return serialization.load_pem_private_key(data, password=password, backend=default_backend())
        elif b'CERTIFICATE' in data:
            return x509.load_pem_x509_certificate(data, default_backend())
        elif b'CERTIFICATE REQUEST' in data:
            return x509.load_pem_x509_csr(data, default_backend())
    except Exception as e:
        return None
    return None


def get_modulus(obj):
    try:
        if isinstance(obj, (x509.Certificate, x509.CertificateSigningRequest)):
            return obj.public_key().public_numbers().n
        elif isinstance(obj, rsa.RSAPrivateKey):
            return obj.private_numbers().public_numbers.n
    except Exception:
        return None
    return None


def find_files(folder):
    return [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(('.key', '.crt', '.cer', '.csr', '.req', '.pem'))
    ]


def identify_files(folder):
    files = find_files(folder)
    results = {"key": None, "cert": None, "csr": None}
    for f in files:
        obj = load_pem_file(f)
        if obj is None:
            continue
        if isinstance(obj, rsa.RSAPrivateKey):
            results["key"] = (f, get_modulus(obj))
        elif isinstance(obj, x509.Certificate):
            results["cert"] = (f, get_modulus(obj))
        elif isinstance(obj, x509.CertificateSigningRequest):
            results["csr"] = (f, get_modulus(obj))
    return results


def compare(folder):
    print(f"\n📁 Checking folder: {folder}")
    items = identify_files(folder)
    found = {k: v for k, v in items.items() if v is not None}

    if len(found) < 2:
        print("⚠️  Not enough valid files found.")
        return

    moduli = [v[1] for v in found.values()]
    if len(set(moduli)) == 1:
        print("✅ All components match:")
        for k, (f, _) in found.items():
            print(f"   - {k.upper()}: {os.path.basename(f)}")
    else:
        print("❌ Mismatch detected:")
        for k, (f, m) in found.items():
            print(f"   - {k.upper()}: {os.path.basename(f)} (modulus: {hex(m)})")
            