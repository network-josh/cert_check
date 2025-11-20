# core/verify_set.py

from __future__ import annotations
from pathlib import Path
from typing import Dict, Tuple

from .crypto_ops import load_pem_object, extract_modulus
from .errors import CertToolError


def verify_folder(folder: str) -> Dict[str, Tuple[str, int]]:
    """
    Scans a folder for key, cert, and CSR files and determines which match.

    Returns dict: {
        "cert": (path, modulus),
        "key":  (path, modulus),
        "csr":  (path, modulus)
    }

    If fewer than 2 loaded or moduli differ, caller must interpret mismatch.
    """
    result: Dict[str, Tuple[str, int]] = {}
    folder_path = Path(folder)

    for file in folder_path.iterdir():
        if not file.is_file():
            continue
        if file.suffix.lower() not in [".key", ".csr", ".crt", ".cer", ".pem", ".req"]:
            continue

        try:
            obj, kind, _ = load_pem_object(str(file))
        except Exception:
            continue

        if not kind or kind not in ["key", "cert", "csr"]:
            continue

        modulus = extract_modulus(obj)
        if modulus is not None and kind not in result:
            result[kind] = (str(file), modulus)

    return result
