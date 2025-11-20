# core/san_ops.py

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address, AddressValueError
from typing import Iterable, List


class SanType(str, Enum):
    """Supported SAN types for this tool."""
    DNS = "dns"
    IP = "ip"


@dataclass(frozen=True)
class SanEntry:
    """
    Represents a single SAN entry.

    type:
        SanType.DNS or SanType.IP
    value:
        The normalized value (lowercase hostname or canonical IP).
    """
    type: SanType
    value: str


def parse_user_sans(raw: str) -> List[SanEntry]:
    """
    Parse a user-provided SAN string into a list of SanEntry objects.

    Supported formats in the raw string:
        - Separated by ',', ';', or whitespace.
        - DNS names: 'app.example.com'
        - IP addresses: '192.0.2.1' or 'ip:192.0.2.1' (case-insensitive)

    Invalid tokens are silently ignored.
    """
    if not raw:
        return []

    tokens: list[str] = []
    # Normalize common separators to semicolons
    for part in raw.replace(",", ";").split(";"):
        tokens.extend(part.split())

    entries: list[SanEntry] = []

    for token in tokens:
        token = token.strip()
        if not token:
            continue

        # Explicit IP prefix: ip:1.2.3.4
        lowered = token.lower()
        if lowered.startswith("ip:"):
            candidate = token[3:].strip()
            _add_ip_entry_if_valid(candidate, entries)
            continue

        # Try bare IP address
        if _looks_like_ip(token):
            _add_ip_entry_if_valid(token, entries)
            continue

        # Otherwise treat as DNS name
        hostname = token.lower()
        if _is_plausible_hostname(hostname):
            entry = SanEntry(SanType.DNS, hostname)
            if entry not in entries:
                entries.append(entry)

    return entries


def _looks_like_ip(text: str) -> bool:
    """Quick heuristic to decide if something might be an IP address."""
    return any(ch.isdigit() for ch in text) and "." in text


def _add_ip_entry_if_valid(text: str, entries: list[SanEntry]) -> None:
    """Validate an IP address and add it as a SAN entry if valid."""
    try:
        ip_obj = ip_address(text.strip())
    except AddressValueError:
        return
    canonical = str(ip_obj)  # normalized representation
    entry = SanEntry(SanType.IP, canonical)
    if entry not in entries:
        entries.append(entry)


def _is_plausible_hostname(hostname: str) -> bool:
    """
    Basic sanity check for hostnames.
    Not a full RFC validator, just keeps obviously bad strings out.
    """
    if len(hostname) == 0 or len(hostname) > 253:
        return False
    if hostname.endswith("."):
        hostname = hostname[:-1]
    labels = hostname.split(".")
    if len(labels) < 1:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        # Must start and end alphanumeric, can contain '-'
        if not (label[0].isalnum() and label[-1].isalnum()):
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
    return True


def apply_default_dns_sans(
    common_name: str,
    existing: Iterable[SanEntry] | None = None,
    include_www: bool = True
) -> list[SanEntry]:
    """
    Ensure that SAN list includes CN and optionally 'www.CN' as DNS SANs.

    - common_name is normalized to lowercase.
    - existing SANs are preserved.
    - No duplicates are added.
    """
    cn = common_name.strip().lower()
    result: list[SanEntry] = []

    if existing:
        # Preserve order, avoid duplicates
        seen = set()
        for san in existing:
            if (san.type, san.value) not in seen:
                result.append(san)
                seen.add((san.type, san.value))

    # Ensure CN DNS SAN
    cn_entry = SanEntry(SanType.DNS, cn)
    if cn_entry not in result:
        result.insert(0, cn_entry)

    # Ensure www.CN DNS SAN if requested
    if include_www:
        www_cn = f"www.{cn}"
        www_entry = SanEntry(SanType.DNS, www_cn)
        if www_entry not in result:
            # Put it right after the CN by default
            result.insert(1, www_entry)

    return result


def format_ms_pki_san_string(entries: Iterable[SanEntry]) -> str:
    """
    Format SAN entries into the Microsoft PKI WEB UI syntax.

    Example:
        entries = [
            SanEntry(DNS, "example.com"),
            SanEntry(DNS, "www.example.com"),
            SanEntry(IP, "192.0.2.10")
        ]

        -> "san:dns=example.com&dns=www.example.com&ip=192.0.2.10"
    """
    parts: list[str] = []
    for san in entries:
        if san.type == SanType.DNS:
            parts.append(f"dns={san.value}")
        elif san.type == SanType.IP:
            parts.append(f"ip={san.value}")
        # Other types (URI/email) could be added in future here.

    return "san:" + "&".join(parts)
