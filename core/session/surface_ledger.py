"""
Surface-Coverage Ledger (PR-C)
==============================
A parallel, **advisory, NON-BLOCKING** record of which re-triggerable skills have
covered which specific surface INSTANCES.

Why it exists
-------------
The static skill-completion gates (``core/session/gates.py``) key on an
endpoint/finding TYPE (a literal ``gate_id``) and a GLOBAL per-skill ``worked``
flag. So a skill runs ONCE — a 2nd AI endpoint, a 2nd host, a new CVE, a new auth
surface never re-triggers it. We deliberately do NOT make the gates per-instance
blocking (a hard per-instance gate makes weak local models game-then-stall).
Instead this ledger tracks per-instance coverage and SURFACES what is still
uncovered, as pure advisory text. It never blocks, never refuses completion.

State (session.json)
--------------------
    surface_coverage = {
        "<skill>": {"unit": "<str>", "discovered": [<key>...], "covered": [<key>...]},
        ...
    }

``discovered``/``covered`` are JSON lists kept de-duped (set semantics). An
``instance_key`` is a short, stable string (a normalized endpoint path, a
host/IP, a CVE id, an ``auth:surface`` tag, …).

Fail-soft invariant
--------------------
Every public mutator is wrapped so a ledger error can NEVER break a tool call, an
endpoint registration, a finding, or completion. All reads/writes go through
session ``_current`` and persist with ``_sess._flush()`` — the same pattern as the
other ``core.session`` submodules (``import core.session as _sess``; attributes
read at call time so the package stays patchable and no import cycle forms).
"""
from __future__ import annotations

import re

import core.session as _sess

# ── Re-triggerable skills and the surface UNIT each one covers ─────────────────
# Only these skills are tracked: their value is realised PER INSTANCE, so a single
# global "ran once" flag under-counts them. Everything else (recon, one-shot
# audits) is left to the existing gates.
SKILL_UNITS: dict[str, str] = {
    "ai-redteam":             "ai_endpoint",
    "post-exploit":           "host",
    "reverse-shell":          "host",
    "lateral-movement":       "host",
    "analyze-cve":            "cve",
    "metasploit":             "cve",
    "credential-audit":       "auth_surface",
    "business-logic":         "workflow_or_identity",
    "container-k8s-security": "cluster_or_pod",
    "cloud-security":         "account_or_identity",
}

# Guard against a pathological / attacker-influenced target unbounded-growing the
# session file — a surface with 200 distinct instances is already well past
# "advisory" usefulness.
_MAX_KEYS = 200

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_UUID_RE = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_NUM_RE = re.compile(r"/\d+")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


# ── Key normalization helpers ──────────────────────────────────────────────────

def _clean(key) -> str:
    """Neutralize + bound an instance key (hosts/CVEs/paths can be target-authored,
    AS-08). Strips control chars/newlines so a key surfaced in the agent's advisory
    text can't inject instruction lines; caps length."""
    if not isinstance(key, str):
        key = str(key)
    return _CTRL.sub("", key).strip()[:256]


def _strip_scheme(s: str) -> str:
    return _SCHEME_RE.sub("", s or "")


def host_key(s: str) -> str:
    """Normalize a target to a comparable host/IP key (drops scheme, path, and a
    single :port). Keeps a bare IPv6 (>=2 colons) intact."""
    s = _strip_scheme(_clean(s))
    s = s.split("/", 1)[0].split("?", 1)[0]
    if s.count(":") == 1:          # host:port (IPv4 / hostname)
        s = s.split(":", 1)[0]
    return s


def _norm_path(p: str) -> str:
    """Collapse numeric/uuid path segments to ``{id}`` — mirrors
    ``core.coverage.classify._normalize_path`` so a discovered endpoint key
    (stored normalized) matches a covered request path."""
    p = _UUID_RE.sub("/{id}", p)
    p = _NUM_RE.sub("/{id}", p)
    return p


def path_key(s: str) -> str:
    """Normalized path component of a URL/target, for ai_endpoint / auth / workflow units."""
    s = _clean(s)
    if not s:
        return ""
    try:
        from urllib.parse import urlparse
        raw = s if "://" in s else ("http://x" + (s if s.startswith("/") else "/" + s))
        path = urlparse(raw).path or "/"
    except Exception:
        path = s
    return _norm_path(path)


# ── Session-state accessors ────────────────────────────────────────────────────

def _coverage_map() -> dict | None:
    """Return (creating if absent) ``_current['surface_coverage']``; None if no session."""
    if not _sess._current:
        return None
    sc = _sess._current.get("surface_coverage")
    if not isinstance(sc, dict):
        sc = {}
        _sess._current["surface_coverage"] = sc
    return sc


def _entry(skill: str, unit: str | None = None) -> dict | None:
    sc = _coverage_map()
    if sc is None:
        return None
    e = sc.get(skill)
    if not isinstance(e, dict):
        e = {"unit": unit or SKILL_UNITS.get(skill, "instance"),
             "discovered": [], "covered": []}
        sc[skill] = e
    else:
        e.setdefault("discovered", [])
        e.setdefault("covered", [])
        if unit and not e.get("unit"):
            e["unit"] = unit
    return e


# ── Public mutators ─────────────────────────────────────────────────────────────

def record_discovered(skill: str, key: str, unit: str | None = None) -> None:
    """Record a DISCOVERED surface instance for ``skill`` (idempotent, fail-soft)."""
    try:
        if skill not in SKILL_UNITS or not _sess._current:
            return
        key = _clean(key)
        if not key:
            return
        e = _entry(skill, unit or SKILL_UNITS[skill])
        if e is None or key in e["discovered"]:
            return
        if len(e["discovered"]) >= _MAX_KEYS:
            return
        e["discovered"].append(key)
        _sess._flush()
    except Exception:
        pass


def record_covered(skill: str, key: str) -> None:
    """Record that ``skill`` COVERED a surface instance (idempotent, fail-soft)."""
    try:
        if skill not in SKILL_UNITS or not _sess._current:
            return
        key = _clean(key)
        if not key:
            return
        e = _entry(skill)
        if e is None or key in e["covered"]:
            return
        e["covered"].append(key)
        _sess._flush()
    except Exception:
        pass


def pending(skill: str) -> list:
    """Uncovered instances for ``skill`` = discovered − covered, in DISCOVERY order
    (severity/novelty isn't tracked per-instance, so discovery order is the priority)."""
    try:
        if not _sess._current:
            return []
        e = (_sess._current.get("surface_coverage") or {}).get(skill)
        if not isinstance(e, dict):
            return []
        covered = set(e.get("covered", []))
        return [k for k in e.get("discovered", []) if k not in covered]
    except Exception:
        return []


def snapshot() -> dict:
    """Deep copy of the whole ``surface_coverage`` map (read API for callers/tests)."""
    try:
        import copy
        if not _sess._current:
            return {}
        return copy.deepcopy(_sess._current.get("surface_coverage", {}) or {})
    except Exception:
        return {}


# ── Covered-attribution (tool TARGET → discovered instance) ─────────────────────

def _instance_core(unit: str, key: str) -> str:
    """The comparable core of a stored instance key (strips the ``web:``/``api:``/
    ``oauth:``/``workflow:`` prefix used by the auth/workflow units)."""
    if unit in ("auth_surface", "workflow_or_identity") and ":" in key:
        return key.split(":", 1)[1]
    return key


def _target_cores(unit: str, target: str) -> set:
    """Candidate comparable cores derived from a firing tool's target, per unit."""
    if unit == "host":
        return {host_key(target)}
    if unit == "cve":
        return {m.upper() for m in _CVE_RE.findall(target)}
    if unit in ("ai_endpoint", "auth_surface", "workflow_or_identity"):
        return {path_key(target), host_key(target)}
    return {_clean(target)}


def _match_instances(unit: str, target: str, discovered: list) -> list:
    """Discovered instances whose core matches the target (exact / containment /
    literal-in-target). Returns [] when nothing matches — caller decides the fallback."""
    t = _clean(target)
    if not t:
        return []
    cores = {c for c in _target_cores(unit, t) if c}
    tl = t.lower()
    out = []
    for k in discovered:
        core = _instance_core(unit, k).lower()
        if not core:
            continue
        hit = any(c.lower() == core or c.lower() in core or core in c.lower() for c in cores)
        if not hit and core in tl:          # e.g. a host literally present in a kali command
            hit = True
        if hit:
            out.append(k)
    return out


def attribute_covered(tool_name: str = "", target: str = "") -> None:
    """Attribute a firing tool to a discovered instance of the ACTIVE skill's unit.

    Called from the hook that already knows the active skill
    (``gates.add_tool_called`` for most tools; ``scan_engine.wrap`` for the
    http_request path that bypasses it). Maps the tool's TARGET to the matching
    discovered ``instance_key`` and marks it covered. If the exact target can't be
    matched, falls back to the SINGLE discovered instance in scope (conservative —
    never over-claims coverage across multiple instances, never raises)."""
    try:
        if not _sess._current:
            return
        active = _sess._current.get("skill")
        if active not in SKILL_UNITS:
            return
        e = (_sess._current.get("surface_coverage") or {}).get(active)
        if not isinstance(e, dict):
            return
        discovered = e.get("discovered", [])
        if not discovered:
            return
        unit = e.get("unit") or SKILL_UNITS[active]
        matches = _match_instances(unit, target, discovered)
        if not matches:
            # Conservative fallback: only when there's a single unambiguous instance.
            if len(discovered) == 1:
                matches = [discovered[0]]
            else:
                return
        for k in matches:
            record_covered(active, k)
    except Exception:
        pass


# ── Surfacer (advisory, read-only) ──────────────────────────────────────────────

def pending_overview(limit_per_skill: int = 5) -> list:
    """Structured advisory: ``[{skill, unit, pending_count, pending[:N]}]`` for every
    tracked skill that still has uncovered instances (empty list when all covered)."""
    out: list = []
    try:
        if not _sess._current:
            return out
        sc = _sess._current.get("surface_coverage") or {}
        for skill, e in sc.items():
            if not isinstance(e, dict):
                continue
            pend = pending(skill)
            if pend:
                out.append({
                    "skill": skill,
                    "unit": e.get("unit") or SKILL_UNITS.get(skill, "instance"),
                    "pending_count": len(pend),
                    "pending": pend[:max(1, limit_per_skill)],
                })
    except Exception:
        pass
    return out


def advisory_line(max_skills: int = 4) -> str:
    """One-line ADVISORY string (empty when nothing is uncovered)."""
    ov = pending_overview()
    if not ov:
        return ""
    parts = []
    for item in ov[:max_skills]:
        keys = ", ".join(item["pending"][:2])
        parts.append(f"{item['skill']} on {keys}")
    return ("Uncovered surface (ADVISORY, non-blocking): " + "; ".join(parts)
            + " — cover in priority order; skipping is allowed.")


def record_skipped_surfaces(reason: str = "budget/time") -> dict:
    """Snapshot the still-uncovered per-instance surface into
    ``_current['skipped_surfaces']`` at completion. ADVISORY ONLY — this records
    pending>0, it NEVER blocks or refuses completion. Returns the snapshot."""
    skipped: dict = {}
    try:
        if not _sess._current:
            return {}
        sc = _sess._current.get("surface_coverage") or {}
        for skill, e in sc.items():
            if not isinstance(e, dict):
                continue
            pend = pending(skill)
            if pend:
                skipped[skill] = {
                    "unit": e.get("unit") or SKILL_UNITS.get(skill, "instance"),
                    "pending": pend,
                    "reason": reason,
                }
        _sess._current["skipped_surfaces"] = skipped
        _sess._flush()
    except Exception:
        pass
    return skipped
