# core/crypto_ops.py

from __future__ import annotations
from typing import Callable, Tuple, Optional, Union
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .errors import EncryptedKeyError, UnsupportedFormatError

PemObject = Union[x509.Certificate, x509.CertificateSigningRequest, rsa.RSAPrivateKey]


def load_pem_object(
    path: str,
    password_callback: Optional[Callable[[str], str]] = None
) -> Tuple[Optional[PemObject], Optional[str], bool]:
    """
    Loads a PEM/DER file and returns:
        (object, type, password_protected)

    type values:
        "key", "cert", "csr", or None

    password_callback:
        function returning password string when needed.
        Should be callable as: password_callback(path)
    """

    with open(path, "rb") as f:
        data = f.read()

    # Try key
    if b"PRIVATE KEY" in data:
        return _load_private_key(path, data, password_callback)

    # Try PEM CSR
    if b"CERTIFICATE REQUEST" in data:
        try:
            return (
                x509.load_pem_x509_csr(data, default_backend()),
                "csr",
                False
            )
        except Exception:
            pass

    # Try PEM Certificate
    if b"BEGIN CERTIFICATE" in data:
        try:
            return (
                x509.load_pem_x509_certificate(data, default_backend()),
                "cert",
                False
            )
        except Exception:
            pass

    # Try DER certificate
    try:
        return (
            x509.load_der_x509_certificate(data, default_backend()),
            "cert",
            False
        )
    except Exception:
        pass

    # Try DER CSR
    try:
        return (
            x509.load_der_x509_csr(data, default_backend()),
            "csr",
            False
        )
    except Exception:
        pass

    raise UnsupportedFormatError(f"Unrecognized file type: {path}")


def _load_private_key(path: str, data: bytes, password_callback) -> Tuple[Optional[rsa.RSAPrivateKey], str, bool]:
    """
    Attempts to load RSA private key with or without a password.
    """

    # Try no password first
    try:
        key = serialization.load_pem_private_key(
            data,
            password=None,
            backend=default_backend()
        )
        return key, "key", False
    except TypeError:
        pass

    # Requires a password
    if not password_callback:
        raise EncryptedKeyError(f"Key is encrypted but no password callback provided: {path}")

    password = password_callback(path)
    if not password:
        raise EncryptedKeyError(f"No password provided for encrypted key: {path}")

    try:
        key = serialization.load_pem_private_key(
            data,
            password=password.encode("utf-8"),
            backend=default_backend()
        )
        return key, "key", True
    except Exception:
        raise EncryptedKeyError(f"Incorrect password for key: {path}")


def extract_modulus(obj: PemObject) -> Optional[int]:
    """
    Returns modulus (n) for RSA objects or None if unsupported.
    """

    try:
        if isinstance(obj, rsa.RSAPrivateKey):
            return obj.private_numbers().public_numbers.n

        if isinstance(obj, rsa.RSAPublicKey):
            return obj.public_numbers().n

        if isinstance(obj, x509.Certificate):
            pub = obj.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                return pub.public_numbers().n

        if isinstance(obj, x509.CertificateSigningRequest):
            pub = obj.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                return pub.public_numbers().n
    except Exception:
        return None

    return None
