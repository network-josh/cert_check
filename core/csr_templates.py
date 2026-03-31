# core/csr_templates.py

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from .csr_ops import SubjectDefaults, KeyUsageDefaults, EkuDefaults
from .errors import CertToolError


def _templates_dir() -> Path:
    from .app_config import load_app_config
    return Path(load_app_config().get("templates_dir", "C:/Certs/templates"))


def _template_path(name: str) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "._- " else "_" for ch in name)
    return _templates_dir() / f"{safe}.json"


def list_templates() -> List[str]:
    d = _templates_dir()
    if not d.exists():
        return []
    return sorted((f.stem for f in d.glob("*.json")), key=str.lower)


def load_template(name: str) -> Optional[dict]:
    path = _template_path(name)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise CertToolError(f"Failed to load template '{name}': {e}")


def save_template(
    name: str,
    subject: SubjectDefaults,
    key_usage: KeyUsageDefaults,
    eku: EkuDefaults,
    key_size: int,
) -> None:
    try:
        d = _templates_dir()
        d.mkdir(parents=True, exist_ok=True)
        data = {
            "subject_defaults": asdict(subject),
            "key_usage": asdict(key_usage),
            "eku": asdict(eku),
            "key_size": key_size,
        }
        _template_path(name).write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        raise CertToolError(f"Failed to save template '{name}': {e}")


def delete_template(name: str) -> None:
    path = _template_path(name)
    if path.exists():
        path.unlink()
