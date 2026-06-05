# core/errors.py

class CertToolError(Exception):
    """Base error type for certificate operations."""

class EncryptedKeyError(CertToolError):
    """Thrown when loading an encrypted key without/with wrong password."""

class UnsupportedFormatError(CertToolError):
    """Thrown when a file does not appear to be cert/key/CSR."""

class ChainFetchError(CertToolError):
    """Raised when an AIA certificate download fails."""
    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(
            f"Failed to fetch certificate from {url}: {reason}\n"
            f"To download manually:  curl -o issuer.der \"{url}\"\n"
            f"                       openssl x509 -inform DER -in issuer.der -out issuer.pem"
        )
