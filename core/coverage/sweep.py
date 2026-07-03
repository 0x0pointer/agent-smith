"""Server-side sweep oracle — pure probe evaluation (SM-5 / SM-10).

No I/O. Given an executed probe (injection type, payload, response), return a
verdict so the sweep orchestrator can either auto-close a cell ``tested_clean``
(artifact-backed) or flag it as a CANDIDATE for the model to confirm + file.

Verdicts
  clean         payload provably had NO effect and the response is normal
                → safe to auto-close tested_clean (a real artifact backs it)
  candidate     an oracle fired (the payload was evaluated/reflected/executed)
                → cell stays pending; the model confirms, files a finding, closes
  blocked       401/403 — auth blocked the payload, the server never evaluated it
                → cell stays pending (matches the injection-cell closure gate)
  inconclusive  couldn't judge honestly (5xx, empty body, unhandled type)
                → cell stays pending; no false-clean is emitted

DESIGN: only the NEGATIVE (clean) verdict auto-mutates the matrix, and only when
the oracle is confidently negative. Positive claims are never auto-filed — that
respects the finding_id integrity gate and the "don't trust a brittle string
oracle for a positive claim" caution. Everything uncertain stays pending.
"""
from __future__ import annotations

import re

# Injection types this oracle can adjudicate. Others (ssrf/xxe/nosqli/idor/…)
# need OOB, multi-request diffing, or human judgment — the sweep leaves them for
# the model rather than guess.
SWEEPABLE = frozenset({"ssti", "xss", "cmdi", "traversal", "sqli"})

_UNIX_FILE_RE = re.compile(r"root:.*?:0:0:")            # /etc/passwd
_WIN_INI_RE = re.compile(r"\bfor 16-bit app support\b|\[extensions\]", re.IGNORECASE)
_CMDI_UNIX_RE = re.compile(r"uid=\d+\(")               # id output
_CMDI_WIN_RE = re.compile(r"(?:\bnt authority\\)|(?:\\\w+\$?\s*$)", re.IGNORECASE)
_SQLMAP_VULN_RE = re.compile(r"is vulnerable|sqlmap identified the following injection|"
                             r"appears to be .* injectable", re.IGNORECASE)
_SQLMAP_CLEAN_RE = re.compile(r"all tested parameters do not appear to be injectable",
                              re.IGNORECASE)


def _verdict(v: str, basis: str) -> dict:
    return {"verdict": v, "basis": basis}


def evaluate_probe(inj_type: str, payload: str, status: int, body: str) -> dict:
    """Adjudicate one executed probe. ``body`` is the response body (http) or the
    tool's stdout (sqlmap). Returns ``{"verdict", "basis"}``."""
    if inj_type not in SWEEPABLE:
        return _verdict("inconclusive", f"{inj_type} not server-side sweepable")

    # sqlmap carries its own verdict in stdout — trust it over a hand oracle.
    if inj_type == "sqli":
        if _SQLMAP_VULN_RE.search(body):
            return _verdict("candidate", "sqlmap reported the parameter injectable")
        if _SQLMAP_CLEAN_RE.search(body):
            return _verdict("clean", "sqlmap: no parameter appears injectable")
        return _verdict("inconclusive", "sqlmap output inconclusive")

    # HTTP-payload oracles below need a response to judge.
    if status in (401, 403):
        return _verdict("blocked", f"auth blocked the payload (HTTP {status})")
    if status >= 500 or not body:
        return _verdict("inconclusive", f"no usable response (HTTP {status})")

    b = body
    if inj_type == "ssti":
        # 7*7=49 for every engine. Evaluated (49 present, literal payload absent)
        # → candidate; literal payload reflected but not evaluated → clean (that's
        # an XSS concern, not SSTI); neither → clean.
        if "49" in b and payload not in b:
            return _verdict("candidate", "arithmetic evaluated (49) — template injection")
        return _verdict("clean", "payload not evaluated by a template engine")

    if inj_type == "xss":
        if payload and payload in b:  # exact, unencoded reflection
            return _verdict("candidate", "payload reflected unencoded in the response")
        return _verdict("clean", "payload absent or encoded in the response")

    if inj_type == "cmdi":
        if _CMDI_UNIX_RE.search(b) or _CMDI_WIN_RE.search(b):
            return _verdict("candidate", "command output present — command injection")
        return _verdict("clean", "no command output in the response")

    if inj_type == "traversal":
        if _UNIX_FILE_RE.search(b) or _WIN_INI_RE.search(b):
            return _verdict("candidate", "file contents leaked — path traversal")
        return _verdict("clean", "no file contents in the response")

    return _verdict("inconclusive", "unhandled")
