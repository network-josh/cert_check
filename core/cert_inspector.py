# core/cert_inspector.py

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from .crypto_ops import load_pem_object, extract_modulus
from .errors import CertToolError


class Severity(str):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


@dataclass
class VerificationPolicy:
    """
    Policy knobs so behavior is tunable later.
    """
    san_missing_severity: str = Severity.ERROR
    san_added_severity: str = Severity.WARN
    ext_missing_severity: str = Severity.WARN
    exp_soon_days: int = 30
    exp_soon_severity: str = Severity.WARN


@dataclass
class CertInfo:
    path: Path
    cn: Optional[str]
    sans: Set[str]
    not_before: datetime
    not_after: datetime
    issuer: str
    serial: int
    modulus: Optional[int]
    key_size: Optional[int]
    sig_hash: Optional[str]
    is_ca: bool
    extensions_oids: Set[str]   # dotted string OIDs
    fingerprint_sha1: str
    fingerprint_sha256: str


@dataclass
class VerificationIssue:
    severity: str
    message: str


@dataclass
class FolderAnalysisResult:
    ok: bool
    issues: List[VerificationIssue]
    cert_groups: Dict[int, List[CertInfo]]
    ca_candidates: List[CertInfo]


def _extract_cn(cert: x509.Certificate) -> Optional[str]:
    try:
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass
    return None


def _extract_sans(cert: x509.Certificate) -> Set[str]:
    sans: Set[str] = set()
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_val = ext.value
        for name in san_val:
            if isinstance(name, x509.DNSName):
                sans.add(name.value.lower())
            elif isinstance(name, x509.IPAddress):
                sans.add(str(name.value))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    return sans


def _extract_key_size(cert: x509.Certificate) -> Optional[int]:
    try:
        pub = cert.public_key()
        if hasattr(pub, "key_size"):
            return pub.key_size
    except Exception:
        return None
    return None


def _extract_sig_hash(cert: x509.Certificate) -> Optional[str]:
    try:
        alg = cert.signature_hash_algorithm
        if alg:
            return alg.name
    except Exception:
        return None
    return None


def _is_ca_cert(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        return bool(bc.ca)
    except x509.ExtensionNotFound:
        return False
    except Exception:
        return False


def _extract_extension_oids(cert: x509.Certificate) -> Set[str]:
    oids: Set[str] = set()
    try:
        for ext in cert.extensions:
            oids.add(ext.oid.dotted_string)
    except Exception:
        pass
    return oids


def _build_cert_info(path: Path) -> Optional[CertInfo]:
    try:
        obj, kind, _ = load_pem_object(str(path))
    except Exception:
        return None

    if kind != "cert":
        return None

    cert: x509.Certificate = obj  # type: ignore

    cn = _extract_cn(cert)
    sans = _extract_sans(cert)
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    issuer = cert.issuer.rfc4514_string()
    serial = cert.serial_number
    modulus = extract_modulus(cert)
    key_size = _extract_key_size(cert)
    sig_hash = _extract_sig_hash(cert)
    is_ca = _is_ca_cert(cert)
    ext_oids = _extract_extension_oids(cert)
    fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    return CertInfo(
        path=path,
        cn=cn,
        sans=sans,
        not_before=not_before,
        not_after=not_after,
        issuer=issuer,
        serial=serial,
        modulus=modulus,
        key_size=key_size,
        sig_hash=sig_hash,
        is_ca=is_ca,
        extensions_oids=ext_oids,
        fingerprint_sha1=fingerprint_sha1,
        fingerprint_sha256=fingerprint_sha256,
    )


def load_certs_from_folder(folder: str) -> List[CertInfo]:
    folder_path = Path(folder)
    if not folder_path.is_dir():
        raise CertToolError(f"{folder} is not a directory")

    certs: List[CertInfo] = []
    for f in folder_path.iterdir():
        if not f.is_file():
            continue
        if f.suffix.lower() not in [".crt", ".cer", ".pem"]:
            # You can expand this if you have other cert extensions
            continue

        info = _build_cert_info(f)
        if info:
            certs.append(info)

    return certs


def group_certs_by_modulus(certs: List[CertInfo]) -> Dict[int, List[CertInfo]]:
    groups: Dict[int, List[CertInfo]] = {}
    for ci in certs:
        if ci.modulus is None:
            # put modulus-less certs in their own bucket keyed by serial
            # but for now we just ignore them from grouping
            continue
        groups.setdefault(ci.modulus, []).append(ci)
    return groups


def analyze_folder(folder: str, policy: Optional[VerificationPolicy] = None) -> FolderAnalysisResult:
    """
    High-level entry point:
      - load all certs
      - group by modulus (old vs new per key)
      - compare CN, SANs, expiry, extensions
      - collect CA-like certs in the folder
    """
    if policy is None:
        policy = VerificationPolicy()

    certs = load_certs_from_folder(folder)
    issues: List[VerificationIssue] = []

    if not certs:
        issues.append(VerificationIssue(Severity.ERROR, "No certificates found in folder."))
        return FolderAnalysisResult(False, issues, {}, [])

    # Identify CA-like certs
    ca_candidates = [c for c in certs if c.is_ca]

    # Group by modulus (per key)
    groups = group_certs_by_modulus(certs)

    # For any certs without modulus (shouldn't really happen for RSA), treat as standalone
    standalone = [c for c in certs if c.modulus is None]
    for c in standalone:
        groups[id(c)] = [c]  # unique key

    # Compare within each group
    ok = True
    now = datetime.utcnow()

    for mod, group in groups.items():
        if not group:
            continue

        # Sort by not_after (expiry) oldest -> newest
        group_sorted = sorted(group, key=lambda c: c.not_after)
        newest = group_sorted[-1]
        oldest = group_sorted[0]

        # Basic group heading
        issues.append(
            VerificationIssue(
                Severity.INFO,
                f"Key group (modulus hash={_short_mod_hash(newest.modulus)}): {len(group_sorted)} cert(s)"
            )
        )
        for c in group_sorted:
            issues.append(
                VerificationIssue(
                    Severity.INFO,
                    f"  {c.path.name}: CN={c.cn}, exp={c.not_after.date()}, issuer={c.issuer}"
                )
            )

        # Expiry checks on newest
        if newest.not_after <= now:
            ok = False
            issues.append(
                VerificationIssue(
                    Severity.ERROR,
                    f"Newest cert {newest.path.name} is already expired ({newest.not_after})."
                )
            )
        else:
            delta = newest.not_after - now
            if delta <= timedelta(days=policy.exp_soon_days):
                issues.append(
                    VerificationIssue(
                        policy.exp_soon_severity,
                        f"Newest cert {newest.path.name} expires in {delta.days} day(s)."
                    )
                )

        # Only one cert in group: no old/new comparison needed
        if len(group_sorted) == 1:
            continue

        # Compare newest against previous in group (oldest, or each older)
        for older in group_sorted[:-1]:
            _compare_cert_pair(older, newest, policy, issues, key_group_ok=lambda v: _update_ok(v, lambda: ok))

        # If any ERROR issue created in this group, mark ok False
        if any(i.severity == Severity.ERROR for i in issues):
            ok = False

    return FolderAnalysisResult(ok, issues, groups, ca_candidates)


def _short_mod_hash(modulus: Optional[int]) -> str:
    if modulus is None:
        return "none"
    text = str(modulus).encode("utf-8")
    h = hashes.Hash(hashes.MD5())
    h.update(text)
    return h.finalize().hex()[:8]


def _update_ok(new_ok: bool, get_ok) -> bool:
    # helper for future if we want to adjust ok per comparison;
    # currently ok is updated at end based on issues
    return get_ok()


def _compare_cert_pair(
    older: CertInfo,
    newer: CertInfo,
    policy: VerificationPolicy,
    issues: List[VerificationIssue],
    key_group_ok
) -> None:
    """
    Compare two certs that share the same modulus (same key),
    treating `older` as old cert and `newer` as replacement.
    """
    # CN must match exactly
    if older.cn and newer.cn and older.cn != newer.cn:
        issues.append(
            VerificationIssue(
                Severity.ERROR,
                f"CN mismatch: old={older.cn}, new={newer.cn} (files {older.path.name} vs {newer.path.name})"
            )
        )

    # SAN comparison
    old_sans = older.sans
    new_sans = newer.sans

    missing_sans = old_sans - new_sans
    added_sans = new_sans - old_sans

    if missing_sans:
        msg = (
            f"New cert {newer.path.name} is missing SAN(s) present in old "
            f"{older.path.name}: {sorted(missing_sans)}"
        )
        issues.append(VerificationIssue(policy.san_missing_severity, msg))

    if added_sans:
        msg = (
            f"New cert {newer.path.name} has additional SAN(s) vs old "
            f"{older.path.name}: {sorted(added_sans)}"
        )
        issues.append(VerificationIssue(policy.san_added_severity, msg))

    # Extension comparison by OID
    old_exts = older.extensions_oids
    new_exts = newer.extensions_oids

    missing_exts = old_exts - new_exts
    added_exts = new_exts - old_exts

    if missing_exts:
        msg = (
            f"New cert {newer.path.name} is missing extension OID(s) present in old "
            f"{older.path.name}: {sorted(missing_exts)}"
        )
        issues.append(VerificationIssue(policy.ext_missing_severity, msg))

    if added_exts:
        msg = (
            f"New cert {newer.path.name} has additional extension OID(s) vs old "
            f"{older.path.name}: {sorted(added_exts)}"
        )
        issues.append(VerificationIssue(Severity.INFO, msg))

    # Issuer change
    if older.issuer != newer.issuer:
        issues.append(
            VerificationIssue(
                Severity.WARN,
                f"Issuer changed: old={older.issuer}, new={newer.issuer}"
            )
        )

    # Key size
    if older.key_size and newer.key_size and newer.key_size < older.key_size:
        issues.append(
            VerificationIssue(
                Severity.WARN,
                f"Key size decreased: old={older.key_size}, new={newer.key_size}"
            )
        )

    # Signature hash algorithm
    if older.sig_hash and newer.sig_hash and older.sig_hash != newer.sig_hash:
        issues.append(
            VerificationIssue(
                Severity.INFO,
                f"Signature hash changed: old={older.sig_hash}, new={newer.sig_hash}"
            )
        )
