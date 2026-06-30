"""
Capabilities loader — discover a skill's declared manual-setup prerequisites.

A skill that needs manual/physical setup ships ``skills/<name>/capabilities.yaml``
(co-located, owned by the skill author). Its PRESENCE is the exception
declaration: absent → Smith runs optimistically. When ``set_skill`` fires for a
skill, this loader reads that file, resolves any ``$ref`` (jailed to
skills/_shared/capabilities/), validates each capability against the probe-verb
allow-list, and opens a (non-blocking) setup gate per unsatisfied capability.

Security:
  - probe commands are validated against core.probe_verbs (no free-form shell).
  - ``$ref`` is confined to skills/_shared/capabilities/ via realpath; traversal
    or symlink-escape is rejected (PLAN_REVIEW_GAPS G21).
  - fail-soft: any parse/validation problem skips that capability with a warning;
    it never raises into the scan loop.
"""
from __future__ import annotations

import re
from pathlib import Path

from core import paths as _paths
from core import probe_verbs

try:
    import yaml
except ImportError:  # pragma: no cover - feature no-ops without a YAML parser
    yaml = None

_SKILLS_DIR = _paths.REPO_ROOT / "skills"
_SHARED_DIR = _SKILLS_DIR / "_shared" / "capabilities"
# A $ref names a shared file by stem only — no slashes, no '..', no absolute path.
_REF_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_RUN_ON = {"host", "kali"}


def _parse_yaml(path: Path):
    if yaml is None:
        return None, "PyYAML not available — capabilities.yaml cannot be parsed"
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")), ""
    except (OSError, yaml.YAMLError) as exc:  # type: ignore[union-attr]
        return None, f"failed to read/parse {path.name}: {exc}"


def _resolve_ref(ref) -> tuple[dict | None, str]:
    """Resolve a {$ref: name} to a shared capability dict, jailed to _SHARED_DIR."""
    if not isinstance(ref, str) or not _REF_RE.match(ref):
        return None, f"invalid $ref {ref!r} (must match {_REF_RE.pattern}; no paths)"
    target = _SHARED_DIR / f"{ref}.yaml"
    try:
        rp = target.resolve()
        jail = _SHARED_DIR.resolve()
    except OSError as exc:
        return None, f"$ref {ref!r} resolve error: {exc}"
    if jail != rp.parent:
        return None, f"$ref {ref!r} escapes the shared-capabilities jail"
    if not rp.is_file():
        return None, f"$ref {ref!r} target not found: {rp.name}"
    data, err = _parse_yaml(rp)
    if err:
        return None, err
    if not isinstance(data, dict):
        return None, f"$ref {ref!r}: shared file must be a single capability mapping"
    return data, ""


def _validate_capability(cap: dict) -> tuple[bool, str]:
    """Defensive load-time check (validate_skills.py is the CI gate)."""
    cid = cap.get("id")
    if not cid or not isinstance(cid, str):
        return False, "capability missing a string 'id'"
    runbook = cap.get("runbook", [])
    if runbook and not isinstance(runbook, list):
        return False, f"[{cid}] runbook must be a list"
    probe = cap.get("readiness_probe")
    if probe is not None:
        if not isinstance(probe, dict):
            return False, f"[{cid}] readiness_probe must be a mapping"
        if probe.get("run_on", "host") not in _RUN_ON:
            return False, f"[{cid}] readiness_probe.run_on must be host|kali"
        ok, why = probe_verbs.validate(probe.get("verb", ""), probe.get("args", []) or [])
        if not ok:
            return False, f"[{cid}] readiness_probe {why}"
    return True, "ok"


def load_capabilities(skill_name: str) -> tuple[list[dict], list[str]]:
    """Return (capabilities, warnings) for a skill. Absent file → ([], [])."""
    if not skill_name:
        return [], []
    path = _SKILLS_DIR / skill_name / "capabilities.yaml"
    if not path.is_file():
        return [], []
    data, err = _parse_yaml(path)
    if err:
        return [], [err]
    if not isinstance(data, list):
        return [], [f"{path.name}: top level must be a list of capabilities"]

    caps: list[dict] = []
    warns: list[str] = []
    for item in data:
        if isinstance(item, dict) and "$ref" in item:
            cap, w = _resolve_ref(item["$ref"])
            if w:
                warns.append(w)
            if cap is None:
                continue
        elif isinstance(item, dict):
            cap = item
        else:
            warns.append(f"skipping non-mapping capability entry: {item!r}")
            continue
        ok, why = _validate_capability(cap)
        if not ok:
            warns.append(f"skipping invalid capability: {why}")
            continue
        caps.append(cap)
    return caps, warns


def enqueue_for_skill(skill_name: str) -> tuple[list[dict], list[str]]:
    """Load a skill's capabilities and open a setup gate for each (idempotent).

    Returns (gates_opened, warnings). Non-blocking: opening a gate never stalls
    the scan; the election + probe lifecycle proceeds out of band.
    """
    caps, warns = load_capabilities(skill_name)
    if not caps:
        return [], warns
    import core.session as _sess  # lazy to avoid any import-time cycle
    gates: list[dict] = []
    for cap in caps:
        g = _sess.open_setup_gate(cap, skill=skill_name)
        if g:
            gates.append(g)
    return gates, warns
