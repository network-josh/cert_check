# core/app_config.py

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .errors import CertToolError

APP_CONFIG_PATH = Path("C:/Certs/cert_tool_app.json")

DEFAULT_APP_CONFIG: Dict[str, Any] = {
    # Paths
    "log_dir":            "C:/Certs/logs",
    "default_output_dir": "C:/Certs",
    "templates_dir":      "C:/Certs/templates",

    # UI
    "theme":              "light",   # "light" or "dark"
    "console_timestamps": False,

    # CSR key / usage defaults
    "default_key_size":     2048,
    "ku_digital_signature": True,
    "ku_key_encipherment":  True,
    "eku_server_auth":      True,
    "eku_client_auth":      False,

    # Subject defaults (empty = omitted from CSR subject)
    "subject_country":  "",
    "subject_state":    "",
    "subject_locality": "",
    "subject_org":      "",
    "subject_ou":       "",
}


def load_app_config() -> Dict[str, Any]:
    """
    Load app-wide configuration. Missing keys fall back to defaults.
    Never crashes due to bad or missing JSON.
    """
    if not APP_CONFIG_PATH.exists():
        return DEFAULT_APP_CONFIG.copy()

    try:
        data = json.loads(APP_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_APP_CONFIG.copy()

    cfg = DEFAULT_APP_CONFIG.copy()
    for k, v in data.items():
        cfg[k] = v
    return cfg


def save_app_config(config: Dict[str, Any]) -> None:
    """
    Save only the keys that differ from defaults so the file stays tidy.
    """
    try:
        APP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        to_write = {
            k: v for k, v in config.items()
            if k not in DEFAULT_APP_CONFIG or v != DEFAULT_APP_CONFIG[k]
        }
        APP_CONFIG_PATH.write_text(json.dumps(to_write, indent=2), encoding="utf-8")
    except Exception as e:
        raise CertToolError(f"Failed to save app config: {e}")
