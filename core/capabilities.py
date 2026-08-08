"""
Capabilities loader — discover a skill's declared manual-setup prerequisites.

A skill that needs manual/physical setup ships ``skills/<name>/capabilities.yaml``
(co-located, owned by the skill author). Its PRESENCE is the exception
declaration: absent → Smith runs optimistically. When ``set_skill`` fires for a
skill, this loader reads that file, validates each capability against the
probe-verb allow-list, and opens a (non-blocking) setup gate per capability.

Each skill keeps its capabilities co-located in its own folder
(skills/<name>/capabilities.yaml) — there is no shared/external location, so a
capability needed by two skills is simply declared in each (they are short).

Security:
  - probe commands are validated against core.probe_verbs (no free-form shell).
  - fail-soft: any parse/validation problem skips that capability with a warning;
    it never raises into the scan loop.
"""
from __future__ import annotations

from pathlib import Path

from core import paths as _paths
from core import probe_verbs

try:
    import yaml
except ImportError:  # pragma: no cover - feature no-ops without a YAML parser
    yaml = None

_SKILLS_DIR = _paths.REPO_ROOT / "skills"
_RUN_ON = {"host", "kali"}


def _parse_yaml(path: Path):
    if yaml is None:
        return None, "PyYAML not available — capabilities.yaml cannot be parsed"
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")), ""
    except (OSError, yaml.YAMLError) as exc:  # type: ignore[union-attr]
        return None, f"failed to read/parse {path.name}: {exc}"


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


def _capabilities_path(skill_name: str) -> Path | None:
    """Locate <skill_name>/capabilities.yaml, supporting one level of domain
    nesting (skills/<name>/... OR skills/<domain>/<name>/...). Returns the path
    or None. Flat layout is checked first for speed + backward compatibility."""
    direct = _SKILLS_DIR / skill_name / "capabilities.yaml"
    if direct.is_file():
        return direct
    try:
        for sub in _SKILLS_DIR.iterdir():
            if sub.is_dir():
                nested = sub / skill_name / "capabilities.yaml"
                if nested.is_file():
                    return nested
    except OSError:
        pass
    return None


def load_capabilities(skill_name: str) -> tuple[list[dict], list[str]]:
    """Return (capabilities, warnings) for a skill. Absent file → ([], [])."""
    if not skill_name:
        return [], []
    path = _capabilities_path(skill_name)
    if path is None:
        return [], []
    data, err = _parse_yaml(path)
    if err:
        return [], [err]
    if not isinstance(data, list):
        return [], [f"{path.name}: top level must be a list of capabilities"]

    caps: list[dict] = []
    warns: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            warns.append(f"skipping non-mapping capability entry: {item!r}")
            continue
        ok, why = _validate_capability(item)
        if not ok:
            warns.append(f"skipping invalid capability: {why}")
            continue
        caps.append(item)
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
