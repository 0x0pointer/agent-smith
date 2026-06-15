"""
Coverage matrix — path normalization and endpoint classification.

Pure functions with no shared state: collapse dynamic path segments for
dedup, map a (param_type, value_hint) pair to the injection types that
apply to it, and tag an endpoint path with a high-value type for
trigger-gate routing. The taxonomy tables themselves live in core.taxonomy
(a leaf module); they're aliased here so these functions keep their names.
"""
from __future__ import annotations

import re

from core import taxonomy as _tax

_APPLICABILITY = _tax.APPLICABILITY
_FALLBACK_KEY = _tax.FALLBACK_KEY
_TYPE_PATTERNS = _tax.TYPE_PATTERNS


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


def classify_endpoint(path: str) -> str | None:
    """Return an endpoint type tag for trigger-gate routing, or None if unclassified.

    Checks path patterns in priority order; first match wins.
    """
    for pattern, tag in _TYPE_PATTERNS:
        if pattern.search(path):
            return tag
    return None
