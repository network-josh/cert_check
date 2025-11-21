# core/app_config.py

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict
from .errors import CertToolError

APP_CONFIG_PATH = Path("C:/Certs/cert_tool_app.json")

DEFAULT_APP_CONFIG: Dict[str, Any] = {
    # Logging / console
    "log_dir": "C:/Certs/logs",
    "console_timestamps": False,      # timestamps in the UI console
    "timezone_mode": "system",        # "system" or "region" (region later)
    "timezone_region": None,          # e.g. "America/New_York" when not system

    # UI / theme
    "theme": "light"                  # "light" or "dark"
}


def load_app_config() -> Dict[str, Any]:
    """
    Load application-wide configuration. Missing keys fall back to defaults.
    Never crashes due to bad JSON.
    """
    if not APP_CONFIG_PATH.exists():
        return DEFAULT_APP_CONFIG.copy()

    try:
        raw = APP_CONFIG_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception:
        return DEFAULT_APP_CONFIG.copy()

    cfg = DEFAULT_APP_CONFIG.copy()
    for k, v in data.items():
        cfg[k] = v
    return cfg


def save_app_config(config: Dict[str, Any]) -> None:
    """
    Save application-wide configuration. Writes only what the user has set.
    """
    try:
        APP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Only write keys that differ from defaults, keeps file tidy
        to_write: Dict[str, Any] = {}
        for k, v in config.items():
            if k not in DEFAULT_APP_CONFIG or v != DEFAULT_APP_CONFIG[k]:
                to_write[k] = v
        APP_CONFIG_PATH.write_text(json.dumps(to_write, indent=2), encoding="utf-8")
    except Exception as e:
        raise CertToolError(f"Failed to save app config: {e}")
