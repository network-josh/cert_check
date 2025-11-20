# core/chain_ops.py

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from .crypto_ops import load_pem_object
from .errors import CertToolError


class ChainCandidate:
    def __init__(self, path: Path, subject: str, issuer: str, fingerprint: str, aki_match: bool, issuer_match: bool):
        self.path = path
        self.subject = subject
        self.issuer = issuer
        self.fingerprint = fingerprint
        self.aki_match = aki_match
        self.issuer_match = issuer_match

    @property
    def likely(self) -> bool:
        return self.issuer_match or self.aki_match


def load_leaf_cert(path: str) -> x509.Certificate:
    obj, kind, _ = load_pem_object(path)
    if kind != "cert":
        raise CertToolError(f"Not a certificate: {path}")
    return obj  # type: ignore


def find_chain_candidates(leaf: x509.Certificate, folder: str) -> List[ChainCandidate]:
    """
    Scans a folder of certificates and returns possible chain certs,
    ranked based on matching leaf issuer and AKI/SKI.
    """
    results: List[ChainCandidate] = []

    leaf_issuer = leaf.issuer.rfc4514_string()

    # Extract AKI if present
    try:
        aki_ext = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        leaf_aki = aki_ext.value.key_identifier
    except x509.ExtensionNotFound:
        leaf_aki = None

    folder_path = Path(folder)

    for file in folder_path.iterdir():
        if not file.is_file():
            continue
        if file.suffix.lower() not in [".crt", ".cer", ".pem", ".der"]:
            continue

        try:
            obj, kind, _ = load_pem_object(str(file))
            if kind != "cert":
                continue
            cert: x509.Certificate = obj  # type: ignore
        except Exception:
            continue

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        fingerprint = cert.fingerprint(hashes.SHA1()).hex()

        # Try SKI match
        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski = ski_ext.value.digest
        except x509.ExtensionNotFound:
            ski = None

        aki_match = (leaf_aki is not None and ski is not None and leaf_aki == ski)
        issuer_match = (subject == leaf_issuer)

        results.append(
            ChainCandidate(
                path=file,
                subject=subject,
                issuer=issuer,
                fingerprint=fingerprint,
                aki_match=aki_match,
                issuer_match=issuer_match
            )
        )

    return results
