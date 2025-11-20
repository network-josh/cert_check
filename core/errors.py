# core/errors.py

class CertToolError(Exception):
    """Base error type for certificate operations."""

class EncryptedKeyError(CertToolError):
    """Thrown when loading an encrypted key without/with wrong password."""

class UnsupportedFormatError(CertToolError):
    """Thrown when a file does not appear to be cert/key/CSR."""
