# core/app_config.py
#
# Bootstrap strategy (no %APPDATA% dependency, works on network shares):
#
#   C:/Certs/cert_tool_basedir.txt   ← one-line pointer, created only when
#                                       the user changes the base dir away
#                                       from the default C:/Certs/
#   {base_dir}/cert_tool_app.json    ← full settings, lives IN the cert folder
#
# Startup order:
#   1. Try C:/Certs/cert_tool_basedir.txt  → get base_dir from its contents
#   2. Fall back to C:/Certs/cert_tool_app.json (default case)
#   3. Fall back to built-in defaults (first launch)
#
# Network share example:  change base dir to \\server\CertShare\CertTool\
#   → pointer file at C:/Certs/cert_tool_basedir.txt contains that UNC path
#   → config lives on the share; logs and templates live there too

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .errors import CertToolError

DEFAULT_BASE_DIR = "C:/Certs"

# This file is only written when the base dir changes away from the default.
_POINTER_PATH = Path("C:/Certs/cert_tool_basedir.txt")

_STATIC_DEFAULTS: Dict[str, Any] = {
    "theme":              "light",
    "console_timestamps": False,
    "default_key_size":     2048,
    "ku_digital_signature": True,
    "ku_key_encipherment":  True,
    "eku_server_auth":      True,
    "eku_client_auth":      False,
    "subject_country":  "",
    "subject_state":    "",
    "subject_locality": "",
    "subject_org":      "",
    "subject_ou":       "",
}


def get_base_dir() -> Path:
    """
    Returns the configured base directory, following the pointer file if present.
    Always returns a Path; never raises.
    """
    if _POINTER_PATH.exists():
        try:
            bd = _POINTER_PATH.read_text(encoding="utf-8").strip()
            if bd:
                return Path(bd)
        except Exception:
            pass
    return Path(DEFAULT_BASE_DIR)


def _save_pointer(base_dir: str) -> None:
    """
    Write the pointer file only when base_dir differs from the default.
    If base_dir IS the default, remove the pointer file (no longer needed).
    """
    normalised = str(Path(base_dir)).replace("\\", "/").rstrip("/")
    default    = str(Path(DEFAULT_BASE_DIR)).replace("\\", "/").rstrip("/")

    if normalised == default:
        if _POINTER_PATH.exists():
            try:
                _POINTER_PATH.unlink()
            except Exception:
                pass
        return

    try:
        _POINTER_PATH.parent.mkdir(parents=True, exist_ok=True)
        _POINTER_PATH.write_text(base_dir, encoding="utf-8")
    except Exception:
        pass  # Non-fatal; worst case the next launch defaults to C:/Certs


def get_config_path() -> Path:
    return get_base_dir() / "cert_tool_app.json"


def _build_defaults() -> Dict[str, Any]:
    base = str(get_base_dir()).replace("\\", "/").rstrip("/")
    return {
        "base_dir":           base,
        "log_dir":            f"{base}/logs",
        "default_output_dir": base,
        "templates_dir":      f"{base}/templates",
        **_STATIC_DEFAULTS,
    }


def load_app_config() -> Dict[str, Any]:
    """Load config, filling missing keys from computed defaults."""
    cfg  = _build_defaults()
    path = get_config_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for k, v in data.items():
                cfg[k] = v
        except Exception:
            pass
    return cfg


def save_app_config(config: Dict[str, Any]) -> None:
    """
    Save config to {base_dir}/cert_tool_app.json.
    Updates the pointer file if base_dir changed.
    """
    new_base = config.get("base_dir", DEFAULT_BASE_DIR)
    _save_pointer(new_base)

    config_path = Path(new_base) / "cert_tool_app.json"
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    except Exception as e:
        raise CertToolError(f"Failed to save app config: {e}")
