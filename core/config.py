# core/config.py

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, Any
from .errors import CertToolError

CONFIG_PATH = Path("C:/Certs/cert_tool_config.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "default_key_size": 2048,
    "ku_digital_signature": True,
    "ku_key_encipherment": True,
    "eku_server_auth": True,
    "eku_client_auth": False
    # NOTE: no jurisdiction defaults (country/state/locality/org/ou)
}


def load_config() -> Dict[str, Any]:
    """
    Loads config JSON.
    Missing fields fall back to defaults.
    Never crashes due to bad JSON content.
    """
    if not CONFIG_PATH.exists():
        return DEFAULT_CONFIG.copy()

    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_CONFIG.copy()

    merged = DEFAULT_CONFIG.copy()
    for k, v in data.items():
        merged[k] = v
    return merged


def save_config(config: Dict[str, Any]) -> None:
    """
    Saves config safely without injecting defaults you don't want.
    Only writes what the user has explicitly set.
    """
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

        # Only write keys the user set, not DEFAULT_CONFIG merged output
        user_written = {
            k: v for k, v in config.items()
            if k not in DEFAULT_CONFIG or v != DEFAULT_CONFIG[k]
        }

        CONFIG_PATH.write_text(json.dumps(user_written, indent=2), encoding="utf-8")
    except Exception as e:
        raise CertToolError(f"Failed to save config: {e}")
