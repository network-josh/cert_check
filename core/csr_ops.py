# core/csr_ops.py

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID

from .san_ops import SanEntry, SanType
from .errors import CertToolError


@dataclass
class SubjectDefaults:
    country: str | None = None
    state: str | None = None
    locality: str | None = None
    organization: str | None = None
    organizational_unit: str | None = None


@dataclass
class KeyUsageDefaults:
    digital_signature: bool = True
    key_encipherment: bool = True
    # You can add more when needed


@dataclass
class EkuDefaults:
    server_auth: bool = True
    client_auth: bool = False


@dataclass
class CsrSpec:
    """
    Specification for generating a single CSR and key pair.
    """
    common_name: str
    sans: List[SanEntry]
    subject_defaults: SubjectDefaults
    key_usage: KeyUsageDefaults
    eku: EkuDefaults
    key_size: int = 2048


@dataclass
class CsrResult:
    """
    Result paths for a generated CSR and keys.
    """
    csr_pem: Path
    csr_der: Optional[Path]
    key_unencrypted: Path
    key_encrypted: Optional[Path]


def generate_csr_and_keys(
    spec: CsrSpec,
    output_dir: str | Path,
    key_password: Optional[str] = None,
    export_der: bool = False
) -> CsrResult:
    """
    Generate an RSA key pair and CSR based on the provided specification.

    - output_dir: directory where key/CSR files will be written.
    - key_password: if provided, an encrypted .enc.key will also be written.
    - export_der: if true, writes a DER version of the CSR as well.

    Returns: CsrResult with all relevant output paths.
    """
    out_dir = Path(output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if spec.key_size < 2048:
        raise CertToolError("Key size must be at least 2048 bits for RSA.")

    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=spec.key_size,
        backend=default_backend()
    )

    # Build subject
    name_attrs: list[x509.NameAttribute] = []

    if spec.subject_defaults.country:
        name_attrs.append(
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, spec.subject_defaults.country)
        )
    if spec.subject_defaults.state:
        name_attrs.append(
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, spec.subject_defaults.state)
        )
    if spec.subject_defaults.locality:
        name_attrs.append(
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, spec.subject_defaults.locality)
        )
    if spec.subject_defaults.organization:
        name_attrs.append(
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, spec.subject_defaults.organization)
        )
    if spec.subject_defaults.organizational_unit:
        name_attrs.append(
            x509.NameAttribute(
                x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
                spec.subject_defaults.organizational_unit
            )
        )

    cn = spec.common_name.strip()
    name_attrs.append(
        x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)
    )

    subject = x509.Name(name_attrs)

    # CSR builder
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    if spec.sans:
        dns_names = [s.value for s in spec.sans if s.type == SanType.DNS]
        ip_addrs = [s.value for s in spec.sans if s.type == SanType.IP]

        san_objs: list[x509.GeneralName] = []
        if dns_names:
            san_objs.extend(x509.DNSName(host) for host in dns_names)
        if ip_addrs:
            from ipaddress import ip_address
            san_objs.extend(x509.IPAddress(ip_address(ip)) for ip in ip_addrs)

        if san_objs:
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName(san_objs),
                critical=False
            )

    # Key Usage
    ku = x509.KeyUsage(
        digital_signature=spec.key_usage.digital_signature,
        key_encipherment=spec.key_usage.key_encipherment,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )
    csr_builder = csr_builder.add_extension(ku, critical=True)

    # EKU
    eku_oids: list[ExtendedKeyUsageOID] = []
    if spec.eku.server_auth:
        eku_oids.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if spec.eku.client_auth:
        eku_oids.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    if eku_oids:
        csr_builder = csr_builder.add_extension(
            x509.ExtendedKeyUsage(eku_oids),
            critical=False
        )

    csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

    # Safe base name from CN
    safe_cn = _safe_filename_from_cn(cn)

    key_unenc_path = out_dir / f"{safe_cn}.key"
    key_enc_path: Optional[Path] = None
    csr_pem_path = out_dir / f"{safe_cn}.csr"
    csr_der_path: Optional[Path] = None

    # Write unencrypted key
    key_unenc_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    key_unenc_path.write_bytes(key_unenc_bytes)

    # Write encrypted key if requested
    if key_password:
        key_enc_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                key_password.encode("utf-8")
            )
        )
        key_enc_path = out_dir / f"{safe_cn}.enc.key"
        key_enc_path.write_bytes(key_enc_bytes)

    # Write CSR PEM
    csr_pem_bytes = csr.public_bytes(serialization.Encoding.PEM)
    csr_pem_path.write_bytes(csr_pem_bytes)

    # Optional DER
    if export_der:
        csr_der_bytes = csr.public_bytes(serialization.Encoding.DER)
        csr_der_path = out_dir / f"{safe_cn}.csr.der"
        csr_der_path.write_bytes(csr_der_bytes)

    return CsrResult(
        csr_pem=csr_pem_path,
        csr_der=csr_der_path,
        key_unencrypted=key_unenc_path,
        key_encrypted=key_enc_path
    )


def _safe_filename_from_cn(cn: str) -> str:
    """
    Convert a CN into a filesystem-safe base name.
    """
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(ch if ch in allowed else "_" for ch in cn)
