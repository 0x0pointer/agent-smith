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
_normalize_param_type = _tax.normalize_param_type


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


def _refine_by_name(name: str, base_types: list[str]) -> list[str]:
    """Narrow the type-based fan-out when a param NAME is unambiguously scoped.

    Conservative (AR-B4): only narrow-intent names (redirect/url/file/command)
    refine; generic content params keep the full fan-out. Intersects toward the
    refinement so it can only narrow, never widen; never returns empty.
    """
    n = (name or "").strip().lower()
    if not n:
        return base_types
    tokens = {t for t in re.split(r"[^a-z0-9]+", n) if t}
    for needles, targeted in _tax.NAME_REFINEMENTS:
        # exact token match, or a long compound needle appearing as a substring
        if tokens & set(needles) or any(len(k) >= 5 and k in n for k in needles):
            refined = [t for t in base_types if t in targeted]
            return refined or base_types
    return base_types


def _applicable_types(param_type: str, value_hint: str, name: str = "") -> list[str]:
    """Return list of injection types applicable to a param.

    ``name`` (optional) enables name-aware refinement — passing it narrows the
    set for unambiguously-scoped params; omitting it preserves prior behavior.
    """
    key = f"{param_type}/{value_hint}" if value_hint else f"{param_type}/default"
    if key in _APPLICABILITY:
        base = list(_APPLICABILITY[key])
    else:
        fallback = f"{param_type}/default"
        base = list(_APPLICABILITY.get(fallback, _APPLICABILITY["query/default"]))
    return _refine_by_name(name, base)


def endpoint_value_rank(path: str, params: list[dict] | None = None) -> int:
    """Test-ordering value rank for an endpoint (WF-A1). Lower = tested earlier.

    Ranked by the endpoint-type tag; an object-reference / identity / secret
    param pulls an otherwise-plain endpoint forward (that's where authz bugs live).
    """
    rank = _tax.ENDPOINT_VALUE_RANK.get(classify_endpoint(path), _tax.ENDPOINT_VALUE_DEFAULT)
    for p in params or []:
        toks = {t for t in re.split(r"[^a-z0-9]+", str(p.get("name", "")).lower()) if t}
        if toks & _tax.HIGH_VALUE_PARAM_TOKENS:
            return min(rank, 3)
    return rank


def classify_endpoint(path: str) -> str | None:
    """Return an endpoint type tag for trigger-gate routing, or None if unclassified.

    Checks path patterns in priority order; first match wins.
    """
    for pattern, tag in _TYPE_PATTERNS:
        if pattern.search(path):
            return tag
    return None
