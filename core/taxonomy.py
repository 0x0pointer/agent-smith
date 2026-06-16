"""
Security taxonomy
=================
The injection/endpoint knowledge that drives coverage-matrix generation and
the cell-closure gates, in one place. Previously these tables were spread
across coverage/classify.py and coverage/validation.py and (for
BYPASS_REQUIRED_TYPES) re-imported from coverage by other modules — which
forced a circular-import workaround. As a **leaf** module (imports only
``re``), anything may depend on it without a cycle.

Consumers alias these (e.g. ``_APPLICABILITY = _tax.APPLICABILITY``) so their
existing local names are unchanged.
"""
from __future__ import annotations

import re

# ── Applicability: which injection types apply to each param type ─────────────
APPLICABILITY: dict[str, list[str]] = {
    # param_type/value_hint
    "path/integer":      ["sqli", "idor", "traversal"],
    "path/string":       ["sqli", "xss", "ssti", "traversal", "cmdi", "idor"],
    "query/default":     ["sqli", "xss", "ssti", "ssrf", "cmdi", "traversal", "redirect", "nosqli", "crlf"],
    "body_form/default": ["sqli", "xss", "ssti", "ssrf", "cmdi", "xxe", "nosqli"],
    "body_json/default": ["sqli", "nosqli", "xss", "ssti", "ssrf", "cmdi", "prototype", "mass_assignment"],
    "header/default":    ["crlf", "xss", "ssrf", "smuggling"],
    "cookie/default":    ["sqli", "xss", "deserial"],
    "endpoint/default":  ["cors", "csrf", "security_headers", "rate_limit", "method_tampering", "cache", "jwt", "race", "bfla"],
}

# Fallback: if no specific hint matches, use param_type/default
FALLBACK_KEY = "{type}/default"

# ── Endpoint-type classification (path pattern → type tag), priority order ────
TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/graphql\b',                   re.IGNORECASE), "graphql"),
    (re.compile(r'/graph\b',                     re.IGNORECASE), "graphql"),
    (re.compile(r'/(?:login|logout|signin|signup|register|auth|oauth|token|sso)\b', re.IGNORECASE), "auth"),
    (re.compile(r'/admin\b',                     re.IGNORECASE), "admin"),
    (re.compile(r'/(?:upload|file|attachment|media|import)\b', re.IGNORECASE), "upload"),
    (re.compile(r'/(?:payment|invoice|checkout|billing|transaction|transfer|balance|wallet)\b', re.IGNORECASE), "financial"),
    (re.compile(r'/(?:ws|websocket|socket)\b', re.IGNORECASE), "websocket"),
    (re.compile(r'(?:/api\b|/v\d+\b)',                  re.IGNORECASE), "api"),
]

# ── Injection types with known bypass techniques — marking these N/A requires
# the notes to explain WHY the bypass doesn't apply. ──────────────────────────
BYPASS_REQUIRED_TYPES: dict[str, str] = {
    "xxe":  "Content-Type switching to application/xml",
    "sqli": "blind boolean/time-based, second-order, or encoding bypass",
    "xss":  "encoding bypass, DOM sinks, or stored via other endpoint",
    "ssti": "alternative template syntax (${}, <%%>, #{}, *{})",
}

# ── Injection cell types where 401/403 is meaningless evidence of cleanliness
# (auth blocked the payload). Excludes auth/access-control types where 401/403
# IS the finding signal. ──────────────────────────────────────────────────────
AUTH_GATED_TYPES = {
    "sqli", "nosqli", "xss", "ssti", "cmdi", "ssrf", "xxe",
    "traversal", "crlf", "prototype", "mass_assignment", "redirect",
}
