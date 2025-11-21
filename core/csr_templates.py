# core/csr_templates.py

from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional

from .csr_ops import SubjectDefaults, KeyUsageDefaults, EkuDefaults
from .errors import CertToolError

TEMPLATES_DIR = Path("C:/Certs/templates")


def _template_path(name: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "._- " else "_" for ch in name)
    return TEMPLATES_DIR / f"{safe}.json"


def list_templates() -> List[str]:
    """
    Return a list of template names (without .json).
    """
    if not TEMPLATES_DIR.exists():
        return []
    names: List[str] = []
    for f in TEMPLATES_DIR.glob("*.json"):
        names.append(f.stem)
    return sorted(names, key=str.lower)


def load_template(name: str) -> Optional[dict]:
    """
    Load a CSR template by name.
    Returns a dict with subject_defaults, key_usage, eku, key_size.
    """
    path = _template_path(name)
    if not path.exists():
        return None

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        return data
    except Exception as e:
        raise CertToolError(f"Failed to load template '{name}': {e}")


def save_template(
    name: str,
    subject: SubjectDefaults,
    key_usage: KeyUsageDefaults,
    eku: EkuDefaults,
    key_size: int
) -> None:
    """
    Save a CSR template to disk.
    """
    try:
        TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "subject_defaults": asdict(subject),
            "key_usage": asdict(key_usage),
            "eku": asdict(eku),
            "key_size": key_size
        }
        path = _template_path(name)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        raise CertToolError(f"Failed to save template '{name}': {e}")
