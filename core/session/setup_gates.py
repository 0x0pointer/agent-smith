"""
Manual-setup gate tracking (capabilities.yaml prerequisites).

A *setup gate* is a manual/physical prerequisite a skill declares in its
``capabilities.yaml`` — a jailbroken device, a UART hookup, an emulator on the
network. Unlike ``core.session.gates`` (the skill-chaining completion gates that
BLOCK ``session(complete)``), setup gates are **non-blocking**: an unsatisfied
gate just leaves its dependent work in a clearly-marked skipped state and the
scan still completes. They live under the distinct ``setup_gates`` key so the
completion-blocker machinery (``pending_gates``/``_gate_blockers``) never touches
them.

Lifecycle: open → elect (now|defer|skip) → check (run the readiness probe) →
satisfied|failed. State persists through ``core.session`` (the ``_sess`` alias)
so a gate opened in one turn survives compaction and cross-process reads.
"""
from __future__ import annotations

from datetime import datetime, timezone

import core.session as _sess

# Default freshness window for a green probe result. Beyond this, the probe
# runner re-probes before *consuming* the gate (probe-on-use) so a device that
# was unplugged after the last green check can't close a cell as a false-clean.
_PROBE_TTL_SECONDS = 600


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _asset_satisfies(capability: dict) -> bool:
    """True if a known_assets device already matches the capability's
    ``satisfied_by_assets`` kinds. Suppresses the re-PROMPT only — never the
    probe (the probe still runs on check), and never for requires_host gates."""
    wanted = capability.get("satisfied_by_assets") or []
    if not wanted:
        return False
    kinds = {w.get("kind") for w in wanted if isinstance(w, dict)}
    devices = ((_sess._current or {}).get("known_assets") or {}).get("devices") or []
    return any(isinstance(d, dict) and d.get("kind") in kinds for d in devices)


def open_setup_gate(capability: dict, skill: str = "") -> dict | None:
    """Register a manual-setup gate from a capability dict. Idempotent by id.

    Returns the gate dict, or None if no running session. On (re-)open, if a
    known device already satisfies a NON-host capability the election prompt is
    pre-elected to 'now' (the probe still has to pass on check). A
    ``requires_host`` capability always starts at 'pending_election' — host
    execution demands explicit human opt-in at least once per session (G22).
    """
    _sess._reconcile_if_external_write()
    if _sess._current is None or _sess._current.get("status") != "running":
        return None

    cap_id = capability.get("id")
    if not cap_id:
        return None

    gates = _sess._current.setdefault("setup_gates", [])
    for gate in gates:
        if gate["id"] == cap_id:
            return gate  # already tracked — idempotent

    requires_host = bool(capability.get("requires_host"))
    pre_elected = (not requires_host) and _asset_satisfies(capability)
    gate = {
        "id":                  cap_id,
        "category":            capability.get("category", "other"),
        "description":         capability.get("description", ""),
        "requires_host":       requires_host,
        "runbook":             capability.get("runbook", []),
        "readiness_probe":     capability.get("readiness_probe", {}),
        "satisfied_by_assets": capability.get("satisfied_by_assets", []),
        "skill":               skill,
        "status":              "elected_now" if pre_elected else "pending_election",
        "election":            "now" if pre_elected else None,
        "opened_at":           _now(),
        "probe_result":        None,
    }
    gates.append(gate)
    _sess._flush()
    return gate


def list_setup_gates() -> list[dict]:
    """Return all setup gates for this session."""
    if _sess._current is None:
        return []
    return list(_sess._current.get("setup_gates", []))


def setup_gate_by_id(gate_id: str) -> dict | None:
    """Return a single setup gate by capability id, or None."""
    if _sess._current is None:
        return None
    for gate in _sess._current.get("setup_gates", []):
        if gate.get("id") == gate_id:
            return gate
    return None


def record_election(gate_id: str, choice: str) -> dict | None:
    """Record the operator's election for a gate. choice ∈ now|defer|skip."""
    _sess._reconcile_if_external_write()
    if _sess._current is None:
        return None
    status_map = {"now": "elected_now", "defer": "deferred", "skip": "skipped"}
    new_status = status_map.get(choice)
    if not new_status:
        return None
    for gate in _sess._current.get("setup_gates", []):
        if gate.get("id") == gate_id:
            gate["election"] = choice
            gate["status"] = new_status
            gate["elected_at"] = _now()
            _sess._flush()
            return gate
    return None


def record_probe_result(
    gate_id: str,
    ok: bool,
    artifact_id: str = "",
    stdout_excerpt: str = "",
    ttl_seconds: int = _PROBE_TTL_SECONDS,
) -> dict | None:
    """Store a readiness-probe result on the gate. ok→satisfied, else failed."""
    _sess._reconcile_if_external_write()
    if _sess._current is None:
        return None
    for gate in _sess._current.get("setup_gates", []):
        if gate.get("id") == gate_id:
            gate["probe_result"] = {
                "ok":             bool(ok),
                "at":             _now(),
                "artifact_id":    artifact_id,
                "stdout_excerpt": stdout_excerpt[:500],
                "ttl_seconds":    ttl_seconds,
            }
            gate["status"] = "satisfied" if ok else "failed"
            _sess._flush()
            return gate
    return None


def probe_is_fresh(gate_id: str) -> bool:
    """True if the gate has a green probe result still within its TTL.

    Used for probe-on-use: a consumer re-probes when this returns False rather
    than trusting a stale green cache (G13).
    """
    gate = setup_gate_by_id(gate_id)
    pr = (gate or {}).get("probe_result")
    if not pr or not pr.get("ok"):
        return False
    try:
        at = datetime.fromisoformat(pr["at"])
    except (ValueError, KeyError, TypeError):
        return False
    age = (datetime.now(timezone.utc) - at).total_seconds()
    return age <= pr.get("ttl_seconds", _PROBE_TTL_SECONDS)
