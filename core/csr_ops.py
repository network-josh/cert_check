# core/csr_ops.py

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID

from .san_ops import SanEntry, SanType
from .errors import CertToolError, EncryptedKeyError


@dataclass
class SubjectDefaults:
    country:             str | None = None
    state:               str | None = None
    locality:            str | None = None
    organization:        str | None = None
    organizational_unit: str | None = None


@dataclass
class KeyUsageDefaults:
    digital_signature: bool = True
    key_encipherment:  bool = True


@dataclass
class EkuDefaults:
    server_auth: bool = True
    client_auth: bool = False


@dataclass
class CsrSpec:
    """
    Specification for generating a CSR.

    Set existing_key_path to reuse an existing private key instead of
    generating a new one.  If the key is password-protected, supply
    existing_key_password.  key_size is ignored when existing_key_path is set.
    """
    common_name:      str
    sans:             List[SanEntry]
    subject_defaults: SubjectDefaults
    key_usage:        KeyUsageDefaults
    eku:              EkuDefaults
    key_size:         int           = 2048
    existing_key_path:     Optional[str] = None
    existing_key_password: Optional[str] = None


@dataclass
class CsrResult:
    csr_pem:         Path
    csr_der:         Optional[Path]
    key_unencrypted: Optional[Path]   # None when an existing key was reused
    key_encrypted:   Optional[Path]   # None when no password was requested
    key_reused:      bool = False      # True when existing_key_path was used


def generate_csr_and_keys(
    spec:       CsrSpec,
    output_dir: str | Path,
    key_password: Optional[str] = None,
    export_der:   bool = False,
) -> CsrResult:
    """
    Generate (or reuse) a private key and produce a CSR.

    - If spec.existing_key_path is set, that key is loaded and reused;
      no new .key file is written.
    - key_password: if provided AND a new key is generated, an encrypted
      .enc.key is also written.
    - export_der: if True, writes a .csr.der alongside the PEM CSR.
    """
    out_dir = Path(output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Key acquisition ───────────────────────────────────────────────
    key_reused = False
    if spec.existing_key_path:
        private_key = _load_existing_key(
            spec.existing_key_path, spec.existing_key_password
        )
        key_reused = True
    else:
        if spec.key_size < 2048:
            raise CertToolError("Key size must be at least 2048 bits for RSA.")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=spec.key_size,
            backend=default_backend(),
        )

    # ── Subject ───────────────────────────────────────────────────────
    name_attrs: list[x509.NameAttribute] = []
    sd = spec.subject_defaults
    if sd.country:             name_attrs.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME,              sd.country))
    if sd.state:               name_attrs.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME,    sd.state))
    if sd.locality:            name_attrs.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME,             sd.locality))
    if sd.organization:        name_attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME,         sd.organization))
    if sd.organizational_unit: name_attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME,  sd.organizational_unit))

    cn = spec.common_name.strip()
    name_attrs.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, cn))
    subject = x509.Name(name_attrs)

    # ── CSR builder ───────────────────────────────────────────────────
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    if spec.sans:
        dns_names = [s.value for s in spec.sans if s.type == SanType.DNS]
        ip_addrs  = [s.value for s in spec.sans if s.type == SanType.IP]
        san_objs: list[x509.GeneralName] = []
        san_objs.extend(x509.DNSName(h) for h in dns_names)
        if ip_addrs:
            from ipaddress import ip_address
            san_objs.extend(x509.IPAddress(ip_address(ip)) for ip in ip_addrs)
        if san_objs:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_objs), critical=False
            )

    ku = x509.KeyUsage(
        digital_signature=spec.key_usage.digital_signature,
        key_encipherment=spec.key_usage.key_encipherment,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    builder = builder.add_extension(ku, critical=True)

    eku_oids = []
    if spec.eku.server_auth: eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if spec.eku.client_auth: eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if eku_oids:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku_oids), critical=False
        )

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    # ── Write output ──────────────────────────────────────────────────
    safe_cn      = _safe_filename_from_cn(cn)
    csr_pem_path = out_dir / f"{safe_cn}.csr"
    csr_der_path: Optional[Path] = None
    key_unenc_path: Optional[Path] = None
    key_enc_path:   Optional[Path] = None

    csr_pem_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    if export_der:
        csr_der_path = out_dir / f"{safe_cn}.csr.der"
        csr_der_path.write_bytes(csr.public_bytes(serialization.Encoding.DER))

    if not key_reused:
        key_unenc_path = out_dir / f"{safe_cn}.key"
        key_unenc_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        if key_password:
            key_enc_path = out_dir / f"{safe_cn}.enc.key"
            key_enc_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        key_password.encode("utf-8")
                    ),
                )
            )

    return CsrResult(
        csr_pem=csr_pem_path,
        csr_der=csr_der_path,
        key_unencrypted=key_unenc_path,
        key_encrypted=key_enc_path,
        key_reused=key_reused,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_existing_key(path: str, password: Optional[str]) -> rsa.RSAPrivateKey:
    """Load a PEM private key from disk; raises CertToolError on failure."""
    try:
        data = Path(path).read_bytes()
    except Exception as e:
        raise CertToolError(f"Cannot read key file: {e}")

    pw_bytes = password.encode("utf-8") if password else None

    try:
        key = serialization.load_pem_private_key(
            data, password=pw_bytes, backend=default_backend()
        )
    except TypeError:
        raise EncryptedKeyError(
            "Key is encrypted — provide the password in the 'Key password' field."
        )
    except ValueError:
        raise EncryptedKeyError("Incorrect password for encrypted key.")
    except Exception as e:
        raise CertToolError(f"Failed to load key: {e}")

    if not isinstance(key, rsa.RSAPrivateKey):
        raise CertToolError("Only RSA private keys are supported for CSR generation.")

    return key


def is_key_encrypted(path: str) -> bool:
    """
    Quick check: returns True if the PEM key at path appears to be encrypted.
    Does NOT fully parse the key — just inspects the PEM header.
    """
    try:
        data = Path(path).read_bytes()
        # Traditional format:  -----BEGIN RSA PRIVATE KEY-----
        #                      Proc-Type: 4,ENCRYPTED
        # PKCS#8 encrypted:    -----BEGIN ENCRYPTED PRIVATE KEY-----
        if b"ENCRYPTED PRIVATE KEY" in data:
            return True
        if b"Proc-Type: 4,ENCRYPTED" in data:
            return True
        # Confirm by actually trying to load without password
        serialization.load_pem_private_key(data, password=None, backend=default_backend())
        return False
    except TypeError:
        return True
    except Exception:
        return False


def _safe_filename_from_cn(cn: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(ch if ch in allowed else "_" for ch in cn)
