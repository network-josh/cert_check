# core/verify_set.py

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional, Tuple

from .crypto_ops import load_pem_object, extract_modulus
from .errors import CertToolError

# (path, md5_of_modulus | None, modulus | None)
SlotResult = Tuple[str, Optional[str], Optional[int]]


def _mod_md5(modulus: int) -> str:
    return hashlib.md5(str(modulus).encode()).hexdigest()


def verify_files(files: Dict[str, str]) -> Dict[str, SlotResult]:
    """
    Given {slot: path} where slots are any of "key", "cert", "csr", "old_cert",
    return {slot: (path, md5_hash, modulus)}.

    Files that cannot be loaded get (path, None, None).
    Only slots present in `files` are processed.
    """
    result: Dict[str, SlotResult] = {}
    for slot, path in files.items():
        try:
            obj, _, _ = load_pem_object(path)
            modulus = extract_modulus(obj) if obj is not None else None
            md5 = _mod_md5(modulus) if modulus is not None else None
            result[slot] = (path, md5, modulus)
        except Exception:
            result[slot] = (path, None, None)
    return result


def check_match(results: Dict[str, SlotResult]) -> Tuple[bool, Optional[str]]:
    """
    Returns (all_match, common_md5).
    all_match is True only when every loaded slot has the same non-None md5.
    """
    hashes = {md5 for _, md5, _ in results.values() if md5 is not None}
    if not hashes:
        return False, None
    if len(hashes) == 1:
        return True, next(iter(hashes))
    return False, None


def scan_folder(folder: str) -> Dict[str, SlotResult]:
    """
    Scans a folder, picks the first file of each type (key / cert / csr),
    and runs verify_files on them.
    """
    folder_path = Path(folder)
    if not folder_path.is_dir():
        raise CertToolError(f"Not a directory: {folder}")

    found: Dict[str, str] = {}
    for file in folder_path.iterdir():
        if not file.is_file():
            continue
        if file.suffix.lower() not in {".key", ".crt", ".cer", ".csr", ".req", ".pem"}:
            continue
        try:
            _, kind, _ = load_pem_object(str(file))
            if kind and kind not in found:
                found[kind] = str(file)
        except Exception:
            pass

    return verify_files(found)
