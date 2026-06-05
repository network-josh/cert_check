# core/site_ops.py

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

import OpenSSL.SSL as ossl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtensionOID, NameOID,
)

from .chain_ops import (
    _cert_not_after, _format_fingerprint, _subjects_match, _aki_ski_match,
)
from .errors import CertToolError, SiteVerificationError


# ─── Result types ─────────────────────────────────────────────────────────────

@dataclass
class SiteCheckResult:
    name: str
    status: str   # PASS / FAIL / WARN / INFO / SKIP
    detail: str


@dataclass
class SiteVerificationResult:
    host: str
    port: int
    ip_override: Optional[str]
    timestamp: datetime
    overall: str                      # PASS / FAIL / WARN
    checks: List[SiteCheckResult]
    leaf_cert: x509.Certificate
    chain_certs: List[x509.Certificate]   # intermediates as served (leaf excluded)


# ─── TLS connection via PyOpenSSL ─────────────────────────────────────────────

def _fetch_from_server(
    hostname: str,
    connect_host: str,
    port: int,
    timeout: int,
) -> tuple[x509.Certificate, List[x509.Certificate], Optional[bytes]]:
    """
    Open a TLS connection and collect the certificate chain as served and any
    OCSP staple.  Returns (leaf_cert, intermediates, staple_bytes).

    Uses PyOpenSSL so the full chain and OCSP staple are accessible — Python's
    standard ssl module exposes neither.

    Manual equivalent:
        openssl s_client -connect <host>:<port> -servername <hostname> -showcerts
        openssl s_client -connect <host>:<port> -servername <hostname> -status
    """
    staple: List[bytes] = []

    def _ocsp_callback(conn, response_bytes, data):
        if response_bytes:
            staple.append(response_bytes)
        return True  # returning False aborts the handshake

    ctx = ossl.Context(ossl.TLS_METHOD)
    ctx.set_verify(ossl.VERIFY_NONE, lambda conn, cert, err, depth, ok: True)
    ctx.set_ocsp_client_callback(_ocsp_callback, data=None)

    try:
        raw_sock = socket.create_connection((connect_host, port), timeout=timeout)
    except OSError as e:
        raise SiteVerificationError(f"Cannot connect to {connect_host}:{port}: {e}")

    try:
        conn = ossl.Connection(ctx, raw_sock)
        conn.set_tlsext_host_name(hostname.encode("ascii"))
        conn.set_connect_state()
        # PyOpenSSL may raise WantReadError/WantWriteError even on blocking
        # sockets when the handshake requires multiple round trips; loop until
        # the handshake completes or a hard error is raised.
        while True:
            try:
                conn.do_handshake()
                break
            except (ossl.WantReadError, ossl.WantWriteError):
                continue
        chain = conn.get_peer_cert_chain() or []
        staple_bytes = staple[0] if staple else None
    except ossl.Error as e:
        raise SiteVerificationError(f"TLS handshake failed: {e}")
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass

    if not chain:
        raise SiteVerificationError("Server sent no certificate")

    certs = [c.to_cryptography() for c in chain]
    return certs[0], certs[1:], staple_bytes


# ─── Individual checks ────────────────────────────────────────────────────────

def _check_expiry(leaf: x509.Certificate, warn_days: int) -> SiteCheckResult:
    """
    Manual equivalent:
        openssl x509 -in leaf.pem -noout -dates
        openssl x509 -in leaf.pem -noout -checkend <seconds>
    """
    now = datetime.now(timezone.utc)
    na = _cert_not_after(leaf)
    if now > na:
        return SiteCheckResult(
            "Certificate expiration", "FAIL",
            f"Certificate expired {na.date()} ({abs((now - na).days)} days ago)"
        )
    days_left = (na - now).days
    status = "WARN" if days_left <= warn_days else "PASS"
    return SiteCheckResult(
        "Certificate expiration", status,
        f"Expires {na.date()} ({days_left} days remaining)"
    )


def _hostname_matches(hostname: str, pattern: str) -> bool:
    """RFC 2818 hostname / wildcard matching."""
    hostname = hostname.lower().rstrip(".")
    pattern  = pattern.lower().rstrip(".")
    if not pattern.startswith("*."):
        return hostname == pattern
    suffix = pattern[2:]
    if not hostname.endswith("." + suffix):
        return False
    prefix = hostname[: -len("." + suffix)]
    return "." not in prefix and len(prefix) > 0


def _check_san_cn_match(leaf: x509.Certificate, hostname: str) -> SiteCheckResult:
    """
    Verify the target hostname is covered by a SAN, or falls back to CN if
    no SAN extension is present (RFC 2818 §3.1).

    Manual equivalent:
        openssl x509 -in leaf.pem -noout -text | grep -A1 "Subject Alternative"
    """
    try:
        san_ext = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        matched = next(
            (n.value for n in san_ext
             if isinstance(n, x509.DNSName) and _hostname_matches(hostname, n.value)),
            None,
        )
        if matched:
            return SiteCheckResult("SAN/CN match", "PASS",
                                   f"hostname matches SAN: {matched}")
        dns_sans = [n.value for n in san_ext if isinstance(n, x509.DNSName)]
        return SiteCheckResult("SAN/CN match", "FAIL",
            f"'{hostname}' does not match any SAN: {dns_sans}")
    except x509.ExtensionNotFound:
        pass

    # Fall back to CN — deprecated but still used by legacy certs
    for attr in leaf.subject:
        if attr.oid == NameOID.COMMON_NAME:
            if _hostname_matches(hostname, attr.value):
                return SiteCheckResult("SAN/CN match", "WARN",
                    f"hostname matches CN='{attr.value}' — no SAN extension (deprecated)")
            return SiteCheckResult("SAN/CN match", "FAIL",
                f"'{hostname}' does not match CN='{attr.value}' and no SAN extension present")

    return SiteCheckResult("SAN/CN match", "FAIL", "No SAN extension and no CN found")


def _check_self_signed(leaf: x509.Certificate) -> SiteCheckResult:
    """Detect self-signed certificates (subject == issuer)."""
    if leaf.subject.rfc4514_string() == leaf.issuer.rfc4514_string():
        return SiteCheckResult("Self-signed certificate", "WARN",
            "Certificate is self-signed — not issued by a CA")
    return SiteCheckResult("Self-signed certificate", "PASS",
        f"Issued by: {leaf.issuer.rfc4514_string()}")


def _check_trusted_ca(
    hostname: str, connect_host: str, port: int, timeout: int
) -> SiteCheckResult:
    """
    Verify the certificate chain against the system trust store by attempting
    a second connection with full certificate verification enabled.

    Manual equivalent:
        openssl s_client -connect <host>:<port> -servername <hostname>
        # exits 0 if trusted, 1 if not
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname):
                return SiteCheckResult("Trusted CA", "PASS",
                    "Chain verified against system trust store")
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message if hasattr(e, "verify_message") else str(e)
        return SiteCheckResult("Trusted CA", "FAIL",
            f"Chain not trusted by system store: {msg}")
    except ssl.SSLError as e:
        return SiteCheckResult("Trusted CA", "WARN",
            f"SSL error during trust check: {e}")
    except Exception as e:
        return SiteCheckResult("Trusted CA", "WARN",
            f"Could not complete trust check: {e}")


def _check_weak_sig(leaf: x509.Certificate) -> SiteCheckResult:
    """
    Fail on SHA-1 or MD5 signed certificates.

    Manual equivalent:
        openssl x509 -in leaf.pem -noout -text | grep "Signature Algorithm"
    """
    try:
        alg = leaf.signature_hash_algorithm
        if alg is None:
            return SiteCheckResult("Signature algorithm", "INFO",
                "Cannot determine signature hash algorithm (may be EdDSA)")
        name = alg.name.lower()
        if name in ("md5", "md4", "md2"):
            return SiteCheckResult("Signature algorithm", "FAIL",
                f"Weak algorithm: {alg.name} (cryptographically broken)")
        if name == "sha1":
            return SiteCheckResult("Signature algorithm", "FAIL",
                "Weak algorithm: SHA-1 (deprecated since 2017, rejected by major browsers)")
        return SiteCheckResult("Signature algorithm", "PASS", alg.name)
    except Exception as e:
        return SiteCheckResult("Signature algorithm", "WARN",
            f"Could not determine: {e}")


def _check_key_size(leaf: x509.Certificate) -> SiteCheckResult:
    """
    Warn on RSA < 2048 bits or ECC < 256 bits.

    Manual equivalent:
        openssl x509 -in leaf.pem -noout -text | grep "Public-Key:"
    """
    try:
        pub = leaf.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            bits = pub.key_size
            if bits < 2048:
                return SiteCheckResult("Key size", "FAIL",
                    f"RSA {bits} bits — minimum acceptable is 2048")
            return SiteCheckResult("Key size", "PASS", f"RSA {bits} bits")
        if isinstance(pub, ec.EllipticCurvePublicKey):
            bits = pub.key_size
            curve = pub.curve.name
            if bits < 256:
                return SiteCheckResult("Key size", "WARN",
                    f"ECC {bits}-bit ({curve}) — minimum recommended is 256")
            return SiteCheckResult("Key size", "PASS", f"ECDSA {bits}-bit ({curve})")
        if isinstance(pub, Ed25519PublicKey):
            return SiteCheckResult("Key size", "PASS", "Ed25519 (128-bit security)")
        if isinstance(pub, Ed448PublicKey):
            return SiteCheckResult("Key size", "PASS", "Ed448 (224-bit security)")
        return SiteCheckResult("Key size", "INFO",
            f"Unknown key type: {type(pub).__name__}")
    except Exception as e:
        return SiteCheckResult("Key size", "WARN", f"Could not check: {e}")


def _check_full_chain_served(chain_certs: List[x509.Certificate]) -> SiteCheckResult:
    """
    Detect whether the server sent intermediates or only the leaf.

    Manual equivalent:
        openssl s_client -connect <host>:<port> -servername <host> -showcerts 2>/dev/null \
          | grep -c "BEGIN CERTIFICATE"
    """
    if not chain_certs:
        return SiteCheckResult("Full chain served", "WARN",
            "Server sent only the leaf certificate — clients without cached "
            "intermediates may fail to verify the chain")
    has_root = chain_certs[-1].subject == chain_certs[-1].issuer
    label = (
        f"{len(chain_certs)} intermediate(s) + root"
        if has_root
        else f"{len(chain_certs)} intermediate(s) — root not included (normal)"
    )
    return SiteCheckResult("Full chain served", "PASS", label)


def _check_chain_order(
    leaf: x509.Certificate, chain_certs: List[x509.Certificate]
) -> SiteCheckResult:
    """
    Verify the chain is in the correct order: each cert issued by the next.

    Manual equivalent:
        openssl verify -CAfile chain.pem leaf.pem
    """
    if not chain_certs:
        return SiteCheckResult("Chain order", "SKIP",
            "No intermediates served — cannot check order")

    all_certs = [leaf] + list(chain_certs)
    gaps: list[str] = []
    for i in range(len(all_certs) - 1):
        if not _subjects_match(all_certs[i], all_certs[i + 1]) and \
           not _aki_ski_match(all_certs[i], all_certs[i + 1]):
            gaps.append(f"break between cert[{i}] and cert[{i + 1}]")

    if gaps:
        return SiteCheckResult("Chain order", "FAIL", "; ".join(gaps))
    return SiteCheckResult("Chain order", "PASS",
        f"Leaf + {len(chain_certs)} cert(s) in correct order")


def _check_ocsp_staple(
    staple_bytes: Optional[bytes], absent_severity: str
) -> SiteCheckResult:
    """
    Check for and validate a stapled OCSP response.

    Manual equivalent:
        openssl s_client -connect <host>:<port> -servername <host> -status \
          2>/dev/null | grep "OCSP response"
    """
    if not staple_bytes:
        return SiteCheckResult("OCSP stapling", absent_severity,
            "Server is not sending a stapled OCSP response")
    try:
        resp = x509_ocsp.load_der_ocsp_response(staple_bytes)
        if resp.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
            status = resp.certificate_status
            if status == x509_ocsp.OCSPCertStatus.GOOD:
                return SiteCheckResult("OCSP stapling", "PASS",
                    "Server is stapling a valid OCSP response — status: GOOD")
            if status == x509_ocsp.OCSPCertStatus.REVOKED:
                return SiteCheckResult("OCSP stapling", "FAIL",
                    "Stapled OCSP response shows certificate is REVOKED")
            return SiteCheckResult("OCSP stapling", "WARN",
                "Stapled OCSP response status: UNKNOWN")
        return SiteCheckResult("OCSP stapling", "WARN",
            f"Stapled OCSP response status: {resp.response_status.name}")
    except Exception as e:
        return SiteCheckResult("OCSP stapling", "WARN",
            f"Staple present but could not parse: {e}")


def _check_ocsp(
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    timeout: int,
) -> SiteCheckResult:
    """
    Fetch and check the OCSP revocation status for the leaf certificate.

    Manual equivalent:
        openssl ocsp -issuer issuer.pem -cert leaf.pem \
          -url <ocsp_url> -text -noverify
    """
    # Find OCSP URL
    ocsp_url: Optional[str] = None
    try:
        aia = leaf.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        for desc in aia:
            if desc.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_url = desc.access_location.value
                break
    except x509.ExtensionNotFound:
        pass

    if not ocsp_url:
        return SiteCheckResult("OCSP revocation", "SKIP",
            "No OCSP URL in certificate AIA extension")

    # Build and send request
    try:
        builder = x509_ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(leaf, issuer, hashes.SHA256())
        req_der = builder.build().public_bytes(serialization.Encoding.DER)

        http_req = urllib.request.Request(
            ocsp_url, data=req_der,
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
                "User-Agent": "cert-check-tool/1.0",
            },
        )
        with urllib.request.urlopen(http_req, timeout=timeout) as resp:
            resp_der = resp.read()
    except urllib.error.URLError as e:
        return SiteCheckResult("OCSP revocation", "WARN",
            f"OCSP request failed: {e.reason} — URL: {ocsp_url}")
    except Exception as e:
        return SiteCheckResult("OCSP revocation", "WARN",
            f"OCSP request failed: {e}")

    # Parse response
    try:
        ocsp_resp = x509_ocsp.load_der_ocsp_response(resp_der)
    except Exception as e:
        return SiteCheckResult("OCSP revocation", "WARN",
            f"OCSP response could not be parsed: {e}")

    if ocsp_resp.response_status != x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return SiteCheckResult("OCSP revocation", "WARN",
            f"OCSP responder returned: {ocsp_resp.response_status.name}")

    cert_status = ocsp_resp.certificate_status
    if cert_status == x509_ocsp.OCSPCertStatus.GOOD:
        return SiteCheckResult("OCSP revocation", "PASS",
            f"OCSP status: GOOD — responder: {ocsp_url}")
    if cert_status == x509_ocsp.OCSPCertStatus.REVOKED:
        try:
            rt = ocsp_resp.revocation_time_utc
        except AttributeError:
            rt_naive = ocsp_resp.revocation_time
            rt = rt_naive.replace(tzinfo=timezone.utc) if rt_naive else None
        reason = str(ocsp_resp.revocation_reason) if ocsp_resp.revocation_reason else "unspecified"
        return SiteCheckResult("OCSP revocation", "FAIL",
            f"CERTIFICATE IS REVOKED — reason: {reason}, time: {rt}")
    return SiteCheckResult("OCSP revocation", "WARN",
        "OCSP status: UNKNOWN")


def _check_crl(leaf: x509.Certificate, timeout: int) -> SiteCheckResult:
    """
    Download the CRL and check whether the leaf certificate is listed.
    Note: CRL signature is not verified here — only serial number presence.

    Manual equivalent:
        # Get CRL URL from cert:
        openssl x509 -in leaf.pem -noout -text | grep -A4 "CRL Distribution"
        # Download and inspect CRL:
        curl -s <crl_url> -o crl.der
        openssl crl -in crl.der -inform DER -noout -text | grep <serial>
    """
    crl_url: Optional[str] = None
    try:
        cdp = leaf.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
        for dp in cdp:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_url = name.value
                        break
            if crl_url:
                break
    except x509.ExtensionNotFound:
        pass

    if not crl_url:
        return SiteCheckResult("CRL revocation", "SKIP",
            "No CRL distribution point in certificate")

    try:
        req = urllib.request.Request(crl_url,
            headers={"User-Agent": "cert-check-tool/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            crl_data = resp.read()
    except Exception as e:
        return SiteCheckResult("CRL revocation", "WARN",
            f"CRL download failed: {e} — URL: {crl_url}")

    try:
        crl = x509.load_der_x509_crl(crl_data)
    except Exception:
        try:
            crl = x509.load_pem_x509_crl(crl_data)
        except Exception as e:
            return SiteCheckResult("CRL revocation", "WARN",
                f"CRL could not be parsed: {e}")

    revoked = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if revoked is not None:
        return SiteCheckResult("CRL revocation", "FAIL",
            f"CERTIFICATE IS REVOKED (serial {leaf.serial_number:#x}) — CRL: {crl_url}")

    try:
        next_update = crl.next_update_utc
    except AttributeError:
        nu = crl.next_update
        next_update = nu.replace(tzinfo=timezone.utc) if nu else None

    now = datetime.now(timezone.utc)
    if next_update and now > next_update:
        return SiteCheckResult("CRL revocation", "WARN",
            f"Not in CRL but CRL is stale (next update was {next_update.date()})")

    nu_label = next_update.date() if next_update else "unknown"
    return SiteCheckResult("CRL revocation", "PASS",
        f"Not in CRL (next update: {nu_label}) — {crl_url}")


def _probe_tls_version(
    hostname: str,
    connect_host: str,
    port: int,
    version_label: str,
    tls_version,      # ssl.TLSVersion member
    expect_rejected: bool,
    timeout: int,
    info_if_absent: bool = False,
) -> SiteCheckResult:
    """
    Probe whether the server accepts or rejects a specific TLS version.

    expect_rejected=True  → TLS 1.0/1.1 — we want the server to reject it.
    expect_rejected=False → TLS 1.2/1.3  — we want the server to accept it.
    info_if_absent=True   → TLS 1.3      — absence is INFO, not FAIL.

    Manual equivalent (adjust flag: -tls1 / -tls1_1 / -tls1_2 / -tls1_3):
        openssl s_client -connect <host>:<port> -servername <host> -tls1_2 \
          < /dev/null; echo "exit: $?"
    """
    check_name = f"TLS {'rejected: ' if expect_rejected else 'supported: '}{version_label}"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    except (ssl.SSLError, AttributeError, ValueError):
        return SiteCheckResult(check_name, "SKIP",
            f"Local OpenSSL cannot probe {version_label} — "
            f"likely disabled at system level. Cannot verify server support.")

    connected = False
    error_msg = ""
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname):
                connected = True
    except ssl.SSLError as e:
        error_msg = str(e)
    except socket.timeout:
        error_msg = "timed out"
    except OSError as e:
        error_msg = str(e)

    if expect_rejected:
        if connected:
            return SiteCheckResult(check_name, "FAIL",
                f"Server accepted {version_label} — this version should be disabled")
        return SiteCheckResult(check_name, "PASS",
            f"Server rejected {version_label}"
            + (f" ({error_msg})" if error_msg else ""))
    else:
        if connected:
            return SiteCheckResult(check_name, "PASS",
                f"Server accepted {version_label}")
        absent_status = "INFO" if info_if_absent else "FAIL"
        return SiteCheckResult(check_name, absent_status,
            f"Server does not support {version_label}"
            + (f" ({error_msg})" if error_msg else ""))


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def _should_run(enabled: Optional[set[str]], check_id: str) -> bool:
    """True when no filter is set or the check_id is in the enabled set."""
    return enabled is None or check_id in enabled


def verify_site(
    hostname: str,
    port: int = 443,
    ip_override: Optional[str] = None,
    expiry_warn_days: int = 30,
    timeout: int = 10,
    ocsp_staple_severity: str = "INFO",
    enabled_checks: Optional[set[str]] = None,
    log_callback: Optional[Callable[[str], None]] = None,
) -> SiteVerificationResult:
    """
    Connect to a live host and run certificate and TLS checks.

    hostname       — used for SNI and certificate name matching
    ip_override    — connect to this IP instead of resolving hostname
    enabled_checks — set of check IDs to run; None means run all
    """
    def _log(msg: str) -> None:
        if log_callback:
            log_callback(msg)

    def _run(check_id: str) -> bool:
        return _should_run(enabled_checks, check_id)

    connect_host = ip_override or hostname
    checks: List[SiteCheckResult] = []

    # ── Phase 1: Connect and retrieve chain ───────────────────────────────────
    _log(f"Connecting to {connect_host}:{port} (SNI: {hostname})…")
    leaf, chain_certs, staple_bytes = _fetch_from_server(
        hostname, connect_host, port, timeout
    )
    cn = _leaf_cn(leaf)
    _log(f"Connected — leaf CN={cn}, {len(chain_certs)} intermediate(s) served")

    # ── Phase 2: Certificate-level checks (no network) ────────────────────────
    if any(_run(c) for c in ("expiry", "san_cn", "self_signed", "weak_sig", "key_size")):
        _log("Checking certificate…")
    if _run("expiry"):      checks.append(_check_expiry(leaf, expiry_warn_days))
    if _run("san_cn"):      checks.append(_check_san_cn_match(leaf, hostname))
    if _run("self_signed"): checks.append(_check_self_signed(leaf))
    if _run("weak_sig"):    checks.append(_check_weak_sig(leaf))
    if _run("key_size"):    checks.append(_check_key_size(leaf))

    # ── Phase 3: Chain checks (no network) ────────────────────────────────────
    if any(_run(c) for c in ("full_chain", "chain_order")):
        _log("Checking chain as served…")
    if _run("full_chain"):  checks.append(_check_full_chain_served(chain_certs))
    if _run("chain_order"): checks.append(_check_chain_order(leaf, chain_certs))

    # ── Phase 4: Revocation ───────────────────────────────────────────────────
    if any(_run(c) for c in ("ocsp_staple", "ocsp", "crl")):
        _log("Checking revocation…")
    if _run("ocsp_staple"):
        checks.append(_check_ocsp_staple(staple_bytes, ocsp_staple_severity))
    if _run("ocsp"):
        if chain_certs:
            checks.append(_check_ocsp(leaf, chain_certs[0], timeout))
        else:
            checks.append(SiteCheckResult("OCSP revocation", "SKIP",
                "No issuer cert available (server sent no intermediates)"))
    if _run("crl"):
        checks.append(_check_crl(leaf, timeout))

    # ── Phase 5: System trust store ───────────────────────────────────────────
    if _run("trusted_ca"):
        _log("Verifying against system trust store…")
        checks.append(_check_trusted_ca(hostname, connect_host, port, timeout))

    # ── Phase 6: TLS version probes ───────────────────────────────────────────
    tls_ids = ("tls10", "tls11", "tls12", "tls13")
    if any(_run(c) for c in tls_ids):
        _log("Probing TLS version support…")
    for label, version, reject, info_absent, check_id in [
        ("TLS 1.0", ssl.TLSVersion.TLSv1,   True,  False, "tls10"),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1, True,  False, "tls11"),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2, False, False, "tls12"),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3, False, True,  "tls13"),
    ]:
        if _run(check_id):
            checks.append(_probe_tls_version(
                hostname, connect_host, port,
                label, version, reject, timeout, info_absent,
            ))

    # ── Overall ───────────────────────────────────────────────────────────────
    statuses = {c.status for c in checks}
    overall = "FAIL" if "FAIL" in statuses else ("WARN" if "WARN" in statuses else "PASS")

    return SiteVerificationResult(
        host=hostname,
        port=port,
        ip_override=ip_override,
        timestamp=datetime.now(timezone.utc),
        overall=overall,
        checks=checks,
        leaf_cert=leaf,
        chain_certs=chain_certs,
    )


# ─── Report formatter ─────────────────────────────────────────────────────────

def _leaf_cn(cert: x509.Certificate) -> str:
    try:
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass
    return ""


def _leaf_sans(cert: x509.Certificate) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        return [n.value for n in san if isinstance(n, x509.DNSName)]
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def format_site_report(result: SiteVerificationResult) -> str:
    """
    Return a human-readable plain-text site verification report suitable for
    record-keeping.
    """
    now_str = result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    leaf = result.leaf_cert

    cn = _leaf_cn(leaf)
    na = _cert_not_after(leaf)
    fp = _format_fingerprint(leaf.fingerprint(hashes.SHA256()))
    sans = _leaf_sans(leaf)

    n_pass = sum(1 for c in result.checks if c.status == "PASS")
    n_fail = sum(1 for c in result.checks if c.status == "FAIL")
    n_warn = sum(1 for c in result.checks if c.status == "WARN")
    summary_parts: list[str] = []
    if n_pass: summary_parts.append(f"{n_pass} passed")
    if n_fail: summary_parts.append(f"{n_fail} failed")
    if n_warn: summary_parts.append(f"{n_warn} warnings")

    lines: list[str] = [
        "SITE VERIFICATION REPORT",
        "=" * 55,
        f"Generated:  {now_str}",
        f"Host:       {result.host}:{result.port}",
        f"IP used:    {result.ip_override or '(resolved via DNS)'}",
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
        "Certificate Details",
        "-" * 40,
        f"Subject: {leaf.subject.rfc4514_string()}",
        f"Issuer:  {leaf.issuer.rfc4514_string()}",
        f"Expires: {na.date()}",
    ]
    if sans:
        lines.append(f"SANs:    {', '.join(sans)}")
    lines.append(f"SHA-256: {fp}")

    lines += ["", "Chain As Served", "-" * 40]
        all_certs = [leaf] + list(result.chain_certs)
        for i, cert in enumerate(all_certs):
            subj = cert.subject.rfc4514_string()
            is_leaf = (i == 0)
            is_root = cert.subject == cert.issuer
            tag = " (leaf)" if is_leaf else (" (self-signed root)" if is_root else "")
            lines.append(f"[{i}]  {subj}{tag}")

    host = result.host
    port = result.port
    lines += [
        "",
        "Manual OpenSSL Equivalents",
        "-" * 40,
        "# Connect and show leaf certificate:",
        f'openssl s_client -connect {host}:{port} -servername {host} < /dev/null',
        "",
        "# Show full chain as served:",
        f'openssl s_client -connect {host}:{port} -servername {host} -showcerts < /dev/null',
        "",
        "# Check for OCSP stapling:",
        f'openssl s_client -connect {host}:{port} -servername {host} -status < /dev/null | grep -A20 "OCSP"',
        "",
        "# Probe specific TLS version (replace -tls1_2 with -tls1 / -tls1_1 / -tls1_3):",
        f'openssl s_client -connect {host}:{port} -servername {host} -tls1_2 < /dev/null',
        "",
        "# OCSP check (requires issuer.pem extracted from chain):",
        f"# openssl ocsp -issuer issuer.pem -cert leaf.pem -url <ocsp_url> -text -noverify",
        "",
        "# CRL check:",
        "# curl -s <crl_url> -o crl.der",
        "# openssl crl -in crl.der -inform DER -noout -text",
    ]

    return "\n".join(lines)
