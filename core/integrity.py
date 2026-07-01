"""
Deliverable tamper-evidence (AS-REPUD)
======================================
The engagement's value is a *trustworthy* set of findings. The anti-fabrication
gate protects integrity at write time; this module adds tamper-EVIDENCE at rest:
a detached HMAC-SHA256 signature over ``findings.json`` (written to
``findings.json.sig`` on every save), so a post-hoc edit to the signed deliverable
is detectable by ``verify_file()``.

The HMAC key is minted once per install and stored ``0600`` under ``logs/``
(gitignored, never committed). Threat model note: this is tamper-evidence against
casual/after-the-fact edits and accidental corruption — it is NOT a defense
against an attacker who already has code execution on the box (they could read the
key and re-sign). For that, sign/verify off-box with an operator-held key at export
time; the primitive here (sign_file/verify_file) supports that too.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from core import paths as _paths

_KEY_FILE = _paths.LOGS_DIR / ".integrity_key"


def _key() -> bytes:
    try:
        existing = _KEY_FILE.read_bytes().strip()
        if existing:
            return existing
    except OSError:
        pass
    import secrets

    key = secrets.token_hex(32).encode()
    try:
        _paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(_KEY_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
    except OSError:
        pass  # ephemeral in-memory key for this process
    return key


def sign_file(path) -> str | None:
    """Write a detached HMAC-SHA256 sidecar (``<path>.sig``) over the file's bytes.

    Best-effort — never raises into the caller's save path; returns the hex digest
    or None on failure.
    """
    try:
        p = Path(path)
        sig = hmac.new(_key(), p.read_bytes(), hashlib.sha256).hexdigest()
        sig_path = Path(str(p) + ".sig")
        fd = os.open(str(sig_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, sig.encode())
        finally:
            os.close(fd)
        return sig
    except OSError:
        return None


def verify_file(path) -> bool:
    """Return True iff ``<path>.sig`` matches an HMAC over the file's current bytes."""
    try:
        p = Path(path)
        expected = Path(str(p) + ".sig").read_text().strip()
        actual = hmac.new(_key(), p.read_bytes(), hashlib.sha256).hexdigest()
        return bool(expected) and hmac.compare_digest(expected, actual)
    except OSError:
        return False
