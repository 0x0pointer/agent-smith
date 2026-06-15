"""
Coverage matrix — path normalization and endpoint classification.

Pure functions with no shared state: collapse dynamic path segments for
dedup, map a (param_type, value_hint) pair to the injection types that
apply to it, and tag an endpoint path with a high-value type for
trigger-gate routing.
"""
from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Applicability rules — which injection types apply to each param type
# ---------------------------------------------------------------------------

_APPLICABILITY: dict[str, list[str]] = {
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
_FALLBACK_KEY = "{type}/default"


def _normalize_path(path: str) -> str:
    """Collapse numeric/uuid segments to placeholders for dedup.

    /profile/1  → /profile/{id}
    /profile/2  → /profile/{id}
    /api/users/550e8400-e29b-41d4-a716-446655440000 → /api/users/{id}
    """
    # UUID segments
    path = re.sub(
        r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        '/{id}', path, flags=re.IGNORECASE,
    )
    # Pure numeric segments
    path = re.sub(r'/\d+', '/{id}', path)
    return path


def _applicable_types(param_type: str, value_hint: str) -> list[str]:
    """Return list of injection types applicable to a param."""
    key = f"{param_type}/{value_hint}" if value_hint else f"{param_type}/default"
    if key in _APPLICABILITY:
        return list(_APPLICABILITY[key])
    fallback = f"{param_type}/default"
    return list(_APPLICABILITY.get(fallback, _APPLICABILITY["query/default"]))


_TYPE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/graphql\b',                   re.IGNORECASE), "graphql"),
    (re.compile(r'/graph\b',                     re.IGNORECASE), "graphql"),
    (re.compile(r'/(?:login|logout|signin|signup|register|auth|oauth|token|sso)\b', re.IGNORECASE), "auth"),
    (re.compile(r'/admin\b',                     re.IGNORECASE), "admin"),
    (re.compile(r'/(?:upload|file|attachment|media|import)\b', re.IGNORECASE), "upload"),
    (re.compile(r'/(?:payment|invoice|checkout|billing|transaction|transfer|balance|wallet)\b', re.IGNORECASE), "financial"),
    (re.compile(r'/(?:ws|websocket|socket)\b', re.IGNORECASE), "websocket"),
    (re.compile(r'(?:/api\b|/v\d+\b)',                  re.IGNORECASE), "api"),
]


def classify_endpoint(path: str) -> str | None:
    """Return an endpoint type tag for trigger-gate routing, or None if unclassified.

    Checks path patterns in priority order; first match wins.
    """
    for pattern, tag in _TYPE_PATTERNS:
        if pattern.search(path):
            return tag
    return None
