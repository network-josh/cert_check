# core/chain_ops.py

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from .crypto_ops import load_pem_object
from .errors import CertToolError, ChainFetchError


# ─── Local folder scan (original feature) ────────────────────────────────────

class ChainCandidate:
    def __init__(self, path: Path, subject: str, issuer: str, fingerprint: str,
                 aki_match: bool, issuer_match: bool):
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
    Scan a folder and return certificates that could be chain certs for the leaf,
    ranked by issuer DN match and AKI/SKI match.

    Manual equivalent:
        openssl x509 -in leaf.crt -text -noout | grep "Issuer:"
        # then look for certs in the folder whose Subject matches that Issuer
        openssl x509 -in candidate.crt -text -noout | grep "Subject:"
    """
    results: List[ChainCandidate] = []
    leaf_issuer = leaf.issuer.rfc4514_string()

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

        try:
            ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ski = ski_ext.value.digest
        except x509.ExtensionNotFound:
            ski = None

        aki_match = (leaf_aki is not None and ski is not None and leaf_aki == ski)
        issuer_match = (subject == leaf_issuer)

        results.append(ChainCandidate(
            path=file,
            subject=subject,
            issuer=issuer,
            fingerprint=fingerprint,
            aki_match=aki_match,
            issuer_match=issuer_match,
        ))

    return results


# ─── Shared helpers ───────────────────────────────────────────────────────────

def _cert_not_after(cert: x509.Certificate) -> datetime:
    # cryptography >= 42 exposes not_valid_after_utc (tz-aware); older versions
    # return naive UTC from not_valid_after.
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _cert_not_before(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_before_utc
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _format_fingerprint(fp: bytes) -> str:
    h = fp.hex()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def _subjects_match(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True when child.issuer == parent.subject (child was issued by parent)."""
    return child.issuer.rfc4514_string() == parent.subject.rfc4514_string()


def _aki_ski_match(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True when child's AKI matches parent's SKI."""
    try:
        aki = child.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier
        ski = parent.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
        return aki is not None and ski is not None and aki == ski
    except (x509.ExtensionNotFound, Exception):
        return False


# ─── AIA chain builder ────────────────────────────────────────────────────────

def _get_aia_issuer_url(cert: x509.Certificate) -> Optional[str]:
    """
    Extract the first caIssuers URL from the cert's AIA extension.

    Manual equivalent:
        openssl x509 -in cert.pem -text -noout | grep -A2 "CA Issuers"
    """
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        for desc in aia:
            if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                return desc.access_location.value
    except (x509.ExtensionNotFound, Exception):
        pass
    return None


def _fetch_cert_bytes(url: str, timeout: int) -> bytes:
    """
    Download raw certificate bytes from a URL.

    Manual equivalent:
        curl -o issuer.der "<url>"
        # If PEM: curl -o issuer.pem "<url>"
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "cert-check-tool/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise ChainFetchError(url, f"HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise ChainFetchError(url, str(e.reason))
    except socket.timeout:
        raise ChainFetchError(url, "connection timed out")
    except Exception as e:
        raise ChainFetchError(url, str(e))


def _parse_cert_bytes(data: bytes, url: str) -> x509.Certificate:
    """
    Parse DER or PEM bytes into a Certificate object.

    Manual equivalent:
        openssl x509 -inform DER -in issuer.der -out issuer.pem
        openssl x509 -in issuer.pem -noout -text
    """
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        pass
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        pass
    raise ChainFetchError(url, "downloaded data is not a recognizable certificate")


def build_chain_via_aia(
    leaf: x509.Certificate,
    max_depth: int = 10,
    timeout: int = 10,
    log_callback: Optional[Callable[[str], None]] = None,
) -> List[x509.Certificate]:
    """
    Walk AIA caIssuers URLs upward from the leaf, fetching each issuer cert
    until a self-signed root is reached.

    Returns [intermediate_1, ..., root] — leaf excluded, nearest-to-leaf first.

    Raises ChainFetchError if any download fails.  The error message includes
    the failing URL and the manual curl/openssl commands to download it manually.

    Manual equivalent for the entire process:
        # 1. Find the caIssuers URL in the leaf:
        openssl x509 -in leaf.crt -text -noout | grep -A2 "CA Issuers"
        # 2. Download the intermediate cert:
        curl -o intermediate.der <url>
        openssl x509 -inform DER -in intermediate.der -out intermediate.pem
        # 3. Repeat steps 1-2 for each fetched cert until self-signed
        # 4. Concatenate in order (nearest-to-leaf first):
        cat intermediate.pem root.pem > chain.pem
    """
    chain: List[x509.Certificate] = []
    seen: set[bytes] = set()
    current = leaf

    for depth in range(max_depth):
        url = _get_aia_issuer_url(current)
        if not url:
            if depth == 0:
                raise CertToolError(
                    "Leaf certificate has no AIA caIssuers extension. "
                    "Cannot fetch chain automatically — use Scan Local Folder instead."
                )
            # Reached a cert with no further AIA pointer; treat as end of chain
            break

        if log_callback:
            log_callback(f"Fetching issuer cert from: {url}")

        data = _fetch_cert_bytes(url, timeout)
        issuer_cert = _parse_cert_bytes(data, url)

        fp = issuer_cert.fingerprint(hashes.SHA256())
        if fp in seen:
            break
        seen.add(fp)

        chain.append(issuer_cert)

        if issuer_cert.subject == issuer_cert.issuer:
            # Self-signed root — we're done
            break

        current = issuer_cert

    if not chain:
        raise CertToolError("No issuer certificates could be fetched.")

    return chain


def write_chain_pem(
    chain_certs: List[x509.Certificate],
    output_path: Path,
    include_leaf: bool = False,
    leaf: Optional[x509.Certificate] = None,
) -> None:
    """
    Write the certificate chain to a PEM file.

    Default order: [intermediate_1, ..., root] (leaf excluded)
    With include_leaf=True: [leaf, intermediate_1, ..., root]

    Manual equivalent:
        cat intermediate.pem root.pem > chain.pem               # leaf excluded
        cat leaf.pem intermediate.pem root.pem > chain.pem      # leaf included
    """
    blocks: list[bytes] = []

    if include_leaf and leaf is not None:
        blocks.append(leaf.public_bytes(serialization.Encoding.PEM))

    for cert in chain_certs:
        blocks.append(cert.public_bytes(serialization.Encoding.PEM))

    output_path.write_bytes(b"".join(blocks))


# ─── Chain validator ──────────────────────────────────────────────────────────

@dataclass
class ChainCheckResult:
    name: str
    status: str   # "PASS", "FAIL", "WARN"
    detail: str


@dataclass
class ChainValidationResult:
    overall: str   # "PASS", "FAIL", "WARN"
    checks: List[ChainCheckResult]
    chain_certs: List[x509.Certificate]
    leaf: x509.Certificate


def load_chain_pem(path: str) -> List[x509.Certificate]:
    """
    Load a concatenated chain PEM file and return all certificates in order.
    Expects leaf-excluded format (intermediates → root).

    Manual equivalent:
        openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs -noout
    """
    data = Path(path).read_bytes()
    certs: List[x509.Certificate] = []

    PEM_HEADER = b"-----BEGIN CERTIFICATE-----"
    PEM_FOOTER = b"-----END CERTIFICATE-----"

    start = 0
    while True:
        begin = data.find(PEM_HEADER, start)
        if begin == -1:
            break
        end = data.find(PEM_FOOTER, begin)
        if end == -1:
            break
        end += len(PEM_FOOTER)
        try:
            certs.append(x509.load_pem_x509_certificate(data[begin:end]))
        except Exception:
            pass
        start = end

    if not certs:
        raise CertToolError(f"No certificates found in: {path}")
    return certs


def _verify_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """
    Verify that cert's signature is valid under issuer_cert's public key.
    Supports RSA (PKCS#1 v1.5), ECDSA, Ed25519, and Ed448.

    Manual equivalent:
        openssl verify -partial_chain -CAfile issuer.pem cert.pem
    """
    pub = issuer_cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            hash_alg = cert.signature_hash_algorithm
            if hash_alg is None:
                return False
            # Certificate signatures use PKCS#1 v1.5 padding (RSA-PSS in certs is rare)
            pub.verify(cert.signature, cert.tbs_certificate_bytes,
                       padding.PKCS1v15(), hash_alg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            hash_alg = cert.signature_hash_algorithm
            if hash_alg is None:
                return False
            pub.verify(cert.signature, cert.tbs_certificate_bytes,
                       ec.ECDSA(hash_alg))
        elif isinstance(pub, (Ed25519PublicKey, Ed448PublicKey)):
            # EdDSA algorithms incorporate the hash internally — no separate hash param
            pub.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False  # Unknown key type; skip rather than falsely fail
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def validate_chain(
    leaf: x509.Certificate,
    chain_certs: List[x509.Certificate],
) -> ChainValidationResult:
    """
    Validate a chain against a leaf certificate.  The chain is expected in
    leaf-excluded order: [direct_issuer, ..., root].

    Checks performed (in order):
      1. Chain connects to leaf        — chain[0] issued the leaf
      2. Correct order / no gaps       — each cert issued by the next
      3. Root is self-signed           — chain[-1] issued itself
      4. All CA certs have cA=TRUE     — basicConstraints on each chain cert
      5. No expired certificates       — validity window includes today for all certs
      6. Cryptographic signatures      — each cert signature verified against issuer key
      7. pathLenConstraint             — chain depth within declared limits

    For full RFC 5280 path validation (name constraints, policy constraints,
    CRL/OCSP revocation) use openssl verify or a dedicated PKIX library.

    Manual equivalent for overall validation:
        openssl verify -CAfile chain.pem leaf.crt
    """
    checks: List[ChainCheckResult] = []
    now = datetime.now(timezone.utc)

    if not chain_certs:
        checks.append(ChainCheckResult("Chain not empty", "FAIL", "Chain has no certificates."))
        return ChainValidationResult("FAIL", checks, chain_certs, leaf)

    # ── 1. Chain connects to leaf ─────────────────────────────────────────────
    dn_ok  = _subjects_match(leaf, chain_certs[0])
    aki_ok = _aki_ski_match(leaf, chain_certs[0])
    if dn_ok or aki_ok:
        how: list[str] = []
        if dn_ok:  how.append("issuer DN matches chain[0] subject")
        if aki_ok: how.append("leaf AKI matches chain[0] SKI")
        checks.append(ChainCheckResult("Chain connects to leaf", "PASS", "  |  ".join(how)))
    else:
        checks.append(ChainCheckResult(
            "Chain connects to leaf", "FAIL",
            f"leaf issuer ({leaf.issuer.rfc4514_string()}) does not match "
            f"chain[0] subject ({chain_certs[0].subject.rfc4514_string()})"
        ))

    # ── 2. Correct order / no gaps ────────────────────────────────────────────
    gaps: list[str] = []
    for i in range(len(chain_certs) - 1):
        if not _subjects_match(chain_certs[i], chain_certs[i + 1]) and \
           not _aki_ski_match(chain_certs[i], chain_certs[i + 1]):
            gaps.append(
                f"break between chain[{i}] and chain[{i + 1}]: "
                f"{chain_certs[i].subject.rfc4514_string()} → "
                f"{chain_certs[i + 1].subject.rfc4514_string()}"
            )
    if gaps:
        checks.append(ChainCheckResult("Correct order / no gaps", "FAIL", "; ".join(gaps)))
    else:
        checks.append(ChainCheckResult(
            "Correct order / no gaps", "PASS",
            f"{len(chain_certs)} certificate(s), no gaps"
        ))

    # ── 3. Root is self-signed ────────────────────────────────────────────────
    root = chain_certs[-1]
    if root.issuer.rfc4514_string() == root.subject.rfc4514_string():
        checks.append(ChainCheckResult(
            "Root is self-signed", "PASS",
            root.subject.rfc4514_string()
        ))
    else:
        checks.append(ChainCheckResult(
            "Root is self-signed", "WARN",
            f"Last cert is not self-signed — chain may be incomplete. "
            f"subject={root.subject.rfc4514_string()}, issuer={root.issuer.rfc4514_string()}"
        ))

    # ── 4. All CA certs have basicConstraints cA=TRUE ─────────────────────────
    non_ca: list[str] = []
    for i, cert in enumerate(chain_certs):
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if not bc.ca:
                non_ca.append(f"chain[{i}] ({cert.subject.rfc4514_string()}) has cA=FALSE")
        except x509.ExtensionNotFound:
            non_ca.append(f"chain[{i}] ({cert.subject.rfc4514_string()}) missing BasicConstraints")
    if non_ca:
        checks.append(ChainCheckResult(
            "All CA certs have basicConstraints cA=TRUE", "FAIL", "; ".join(non_ca)
        ))
    else:
        checks.append(ChainCheckResult(
            "All CA certs have basicConstraints cA=TRUE", "PASS",
            f"All {len(chain_certs)} chain cert(s) are CA-capable"
        ))

    # ── 5. No expired certificates ────────────────────────────────────────────
    # Check the leaf and every chain cert
    expired: list[str] = []
    soonest_expiry: Optional[datetime] = None
    soonest_label = ""

    for cert, label in [(leaf, "leaf")] + [(c, f"chain[{i}]")
                                           for i, c in enumerate(chain_certs)]:
        na = _cert_not_after(cert)
        nb = _cert_not_before(cert)
        if now > na:
            expired.append(f"{label} expired {na.date()}")
        elif now < nb:
            expired.append(f"{label} not yet valid (starts {nb.date()})")
        else:
            if soonest_expiry is None or na < soonest_expiry:
                soonest_expiry = na
                soonest_label = f"{label} ({cert.subject.rfc4514_string()})"

    if expired:
        checks.append(ChainCheckResult(
            "No expired certificates", "FAIL", "; ".join(expired)
        ))
    else:
        days_left = (soonest_expiry - now).days if soonest_expiry else 0
        detail = (
            f"Nearest expiry: {soonest_label} on {soonest_expiry.date()} ({days_left} days)"
            if soonest_expiry else "All certificates within validity window"
        )
        checks.append(ChainCheckResult("No expired certificates", "PASS", detail))

    # ── 6. Cryptographic signatures ───────────────────────────────────────────
    # Each cert must be signed by the next cert in chain; root signs itself.
    sig_failures: list[str] = []
    pairs = [(leaf, chain_certs[0], "leaf", "chain[0]")]
    for i in range(len(chain_certs) - 1):
        pairs.append((chain_certs[i], chain_certs[i + 1], f"chain[{i}]", f"chain[{i + 1}]"))
    pairs.append((chain_certs[-1], chain_certs[-1],
                  f"chain[{len(chain_certs) - 1}]", "self (root)"))

    for child, parent, child_lbl, parent_lbl in pairs:
        if not _verify_signature(child, parent):
            sig_failures.append(
                f"{child_lbl} signature invalid under {parent_lbl} public key"
            )

    if sig_failures:
        checks.append(ChainCheckResult(
            "Cryptographic signatures", "FAIL", "; ".join(sig_failures)
        ))
    else:
        checks.append(ChainCheckResult(
            "Cryptographic signatures", "PASS",
            "Each certificate verified against its issuer's public key"
        ))

    # ── 7. pathLenConstraint ──────────────────────────────────────────────────
    # chain_certs[i] has i intermediate CAs between it and the leaf.
    # A pathLenConstraint of N means at most N intermediates may follow below
    # this CA in the path.  The root (self-signed, last in chain) is excluded
    # because pathLen applies only to non-self-issued CAs.
    path_violations: list[str] = []
    for i, cert in enumerate(chain_certs[:-1]):  # exclude root
        try:
            bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if bc.path_length is not None and i > bc.path_length:
                path_violations.append(
                    f"chain[{i}] ({cert.subject.rfc4514_string()}) allows "
                    f"pathLen={bc.path_length} but {i} intermediate(s) follow it"
                )
        except x509.ExtensionNotFound:
            pass

    if path_violations:
        checks.append(ChainCheckResult("pathLenConstraint", "FAIL",
                                       "; ".join(path_violations)))
    else:
        checks.append(ChainCheckResult("pathLenConstraint", "PASS",
                                       "Chain depth within all pathLenConstraint limits"))

    # ── Overall ───────────────────────────────────────────────────────────────
    statuses = {c.status for c in checks}
    overall = "FAIL" if "FAIL" in statuses else ("WARN" if "WARN" in statuses else "PASS")

    return ChainValidationResult(overall, checks, chain_certs, leaf)


# ─── Report formatter ─────────────────────────────────────────────────────────

def format_validation_report(
    leaf_path: str,
    chain_path: str,
    result: ChainValidationResult,
) -> str:
    """
    Return a human-readable plain-text chain validation report suitable for
    saving as a record-keeping artifact.
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    leaf = result.leaf

    leaf_cn = ""
    try:
        for attr in leaf.subject:
            if attr.oid == NameOID.COMMON_NAME:
                leaf_cn = attr.value
                break
    except Exception:
        pass

    leaf_fp = _format_fingerprint(leaf.fingerprint(hashes.SHA256()))

    n_pass = sum(1 for c in result.checks if c.status == "PASS")
    n_fail = sum(1 for c in result.checks if c.status == "FAIL")
    n_warn = sum(1 for c in result.checks if c.status == "WARN")
    summary_parts: list[str] = []
    if n_pass: summary_parts.append(f"{n_pass} passed")
    if n_fail: summary_parts.append(f"{n_fail} failed")
    if n_warn: summary_parts.append(f"{n_warn} warnings")

    lines: list[str] = []
    lines += [
        "CHAIN VALIDATION REPORT",
        "=" * 55,
        f"Generated:  {now_str}",
        f"Leaf:       {leaf_path}",
    ]
    if leaf_cn:
        lines.append(f"              CN={leaf_cn}")
    lines += [
        f"              SHA-256: {leaf_fp}",
        f"Chain file: {chain_path}",
        f"Overall:    {result.overall}  ({', '.join(summary_parts)})",
        "",
        "Checks",
        "-" * 40,
    ]
    for check in result.checks:
        lines.append(f"[{check.status:<4}]  {check.name}")
        if check.detail:
            lines.append(f"          {check.detail}")
    lines += [
        "",
        "Chain Contents",
        "-" * 40,
    ]
    for i, cert in enumerate(result.chain_certs):
        subj = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        na = _cert_not_after(cert)
        nb = _cert_not_before(cert)
        fp = _format_fingerprint(cert.fingerprint(hashes.SHA256()))
        is_root = (subj == issuer)
        root_tag = "  (self-signed root)" if is_root else ""
        lines += [
            f"[{i}]  {subj}{root_tag}",
            f"     Issuer: {issuer}",
            f"     Valid:  {nb.date()} → {na.date()}  |  SHA-256: {fp}",
        ]
    lines += [
        "",
        "Manual OpenSSL Equivalents",
        "-" * 40,
        "# Verify leaf against this chain:",
        f'openssl verify -CAfile "{chain_path}" "{leaf_path}"',
        "",
        "# List all certs in a chain PEM:",
        f'openssl crl2pkcs7 -nocrl -certfile "{chain_path}" | openssl pkcs7 -print_certs -noout',
        "",
        "# Show AIA caIssuers URL(s) in the leaf cert:",
        f'openssl x509 -in "{leaf_path}" -text -noout | grep -A2 "CA Issuers"',
        "",
        "# Download an intermediate manually if AIA fetch fails:",
        "#   curl -o issuer.der <URL from AIA output>",
        "#   openssl x509 -inform DER -in issuer.der -out intermediate.pem",
        "#   Repeat for each level, then concatenate (nearest-to-leaf first):",
        "#   cat intermediate.pem root.pem > chain.pem",
        "",
        "# Verify a single cert's signature against its issuer:",
        "#   openssl verify -partial_chain -CAfile issuer.pem cert.pem",
    ]

    return "\n".join(lines)
