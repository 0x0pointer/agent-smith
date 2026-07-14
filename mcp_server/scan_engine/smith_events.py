"""
Runtime smith-event emitter — Plane A raw capture (training-data-plan.md §3, §8).

Fires from ``scan_engine.wrap()`` once per tool call, emitting a schema-valid ``action`` + ``result``
event pair (validates against ``training-data/schemas/``). Events land as JSONL at
``logs/smith-events/<engagement_id>.jsonl`` — one append-only stream per scan.

Design contract:
  - **Fire-and-forget, fail-soft:** an emit failure NEVER breaks or slows a tool call (mirrors
    quick_log). Every path is wrapped; exceptions are swallowed.
  - **Plane A (raw capture):** redaction to the training store (Plane B) happens at export, NOT here.
    The only at-capture redaction is the kali command (reusing quick_log's ``_redact_cmd``) so raw
    credentials never inline into an event's params.
  - **Objective events only (slice 1):** ``action``/``result`` are derivable at the choke point with
    zero model cooperation. ``decision`` capture (goal/hypothesis/confidence) is a later slice that
    needs an agent-facing affordance — never fabricated post-hoc.

Disable with ``SMITH_EVENTS_DISABLED=1``.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import paths as _paths

_SCHEMA_VERSION = "smith-event/1.0"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # ULID base32 (schema ulid pattern)
_EVENTS_DIR = _paths.REPO_ROOT / "logs" / "smith-events"  # module-level so tests can redirect it

_lock = threading.Lock()
_seq: dict[str, int] = {}  # engagement_id -> last allocated sequence (in-memory, seeded from disk)
_current_decision: dict[str, str] = {}  # engagement_id -> current decision event_id (links following actions)

# Tools that only READ the target — everything else is treated as at-least-reversible.
_READ_ONLY = {"nmap", "naabu", "httpx", "nuclei", "subfinder", "spider", "ffuf", "semgrep",
              "trufflehog", "mobsfscan", "mobsf"}
_STATE_MUTATING = {"kali", "kali_sqlmap", "metasploit"}


def _enabled() -> bool:
    return os.environ.get("SMITH_EVENTS_DISABLED", "").strip().lower() not in ("1", "true", "yes")


def _ulid() -> str:
    """48-bit ms timestamp + 80 random bits, Crockford base32 (26 chars) — sortable + schema-valid."""
    n = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[n & 31])
        n >>= 5
    return "".join(reversed(out))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _engagement_id() -> str | None:
    try:
        from core import session
        s = session.get()
        return (s or {}).get("id")
    except Exception:
        return None


def _next_seq(engagement: str, path: Path) -> int:
    """Monotonic per-engagement sequence. Seeded from the file's line count on first use so it
    survives an MCP-server restart mid-scan (the ordering authority, §3.1)."""
    if engagement not in _seq:
        try:
            _seq[engagement] = sum(1 for _ in path.open()) if path.exists() else 0
        except OSError:
            _seq[engagement] = 0
    _seq[engagement] += 1
    return _seq[engagement]


def _envelope(event_type: str, engagement: str, seq: int, **extra) -> dict:
    now = _now_iso()
    env = {"event_id": _ulid(), "engagement_id": engagement, "event_type": event_type,
           "sequence": seq, "occurred_at": now, "recorded_at": now, "schema_version": _SCHEMA_VERSION}
    env.update({k: v for k, v in extra.items() if v is not None})
    return env


def _redact_command(cmd: str) -> str:
    try:
        from mcp_server.scan_engine.envelope.quick_log import _redact_cmd
        return _redact_cmd(str(cmd))
    except Exception:
        return str(cmd)[:220]


def _params(ctx: dict) -> dict:
    p = {}
    for k in ("method", "url", "target", "action", "operation", "module", "payload_set"):
        v = ctx.get(k)
        if v:
            p[k] = v
    if ctx.get("command"):
        p["command"] = _redact_command(ctx["command"])
    return p


def _safety_class(tool: str, ctx: dict) -> str:
    if tool in _READ_ONLY:
        return "read_only"
    if tool in _STATE_MUTATING:
        return "state_mutating"
    if tool in ("http_request", "http") and (ctx.get("method") or "GET").upper() in ("GET", "HEAD", "OPTIONS"):
        return "read_only"
    return "reversible"


def _family(tool: str, ctx: dict) -> dict:
    return {"target_entity": str(ctx.get("target") or ctx.get("url") or tool),
            "operation_class": tool,
            "payload_family": str(ctx.get("action") or ctx.get("method") or tool)}


def _result_class(result: Any) -> str:
    ev = getattr(result, "evidence", None) or {}
    if ev.get("error"):
        return "error"
    if getattr(result, "anomalies", None):
        return "anomaly"
    return "ok"


def _provenance() -> dict:
    """proposal_source + teacher_origin from the session model (§3, §12). Defaults to open_weight;
    a proprietary model id (if ever recorded) is what would flip it — the export gate keys on this."""
    prov = {"proposal_source": "model", "teacher_origin": "open_weight"}
    try:
        from core import session
        mp = (session.get() or {}).get("model_profile")
        if mp:
            prov["proposal_source"] = f"model:{mp}"
    except Exception:
        pass
    return prov


def _captured(value: Any) -> dict:
    """Wrap a reasoning field as a captured_field (§3). Present ⇒ pre_decision_generated (the agent
    produced it BEFORE acting); absent ⇒ not_captured — NEVER fabricated post-hoc."""
    if value is None:
        return {"value": None, "capture_mode": "not_captured"}
    return {"value": value, "capture_mode": "pre_decision_generated", "actor": "model"}


def emit_decision(data: dict) -> str | None:
    """Emit a schema-valid ``decision`` event from what the agent recorded BEFORE acting (§3). Absent
    reasoning fields are marked ``not_captured``. Stores the decision id so the following ``action``s
    link ``caused_by`` it (decision → action → result). Returns the id, or None. Fail-soft."""
    if not _enabled():
        return None
    try:
        engagement = _engagement_id()
        if not engagement:
            return None
        data = data or {}
        _EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        path = _EVENTS_DIR / f"{engagement}.jsonl"
        supporting = [{"artifact_ref": a, "visible_at_decision": True}
                      for a in (data.get("supporting_observations") or [])
                      if isinstance(a, str) and a.startswith("sha256:")]
        decision = {
            "goal": str(data.get("goal") or ""),
            "hypothesis": data.get("hypothesis"),
            "supporting_observations": supporting,
            "target_ref": data.get("target_ref"),
            "technique": data.get("technique"),
            "alternatives_considered": _captured(data.get("alternatives_considered")),
            "expected_signals": _captured(data.get("expected_signals")),
            "confidence": _captured(data.get("confidence")),
            "stop_condition": _captured(data.get("stop_condition")),
            "chosen_tool": str(data.get("chosen_tool") or ""),
            "operation": str(data.get("operation") or "call"),
            "params": data.get("params") if isinstance(data.get("params"), dict) else {},
            "explanation": (str(data["explanation"])[:400] if data.get("explanation") else None),
            "provenance": _provenance(),
            "context_manifest_id": data.get("context_manifest_id"),
        }
        decision = {k: v for k, v in decision.items() if v is not None}
        with _lock:
            env = _envelope("decision", engagement, _next_seq(engagement, path))
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({**env, "decision": decision}, ensure_ascii=False) + "\n")
            _current_decision[engagement] = env["event_id"]
        return env["event_id"]
    except Exception:
        return None


def emit_finding(data: dict, finding_id: str, proof_artifact_id: str = "") -> None:
    """Emit a ``finding`` event when report(action='finding') files one (§3, §4). caused_by the current
    decision (shared correlation_id) so the graph reads decision → action → result → finding. Fail-soft."""
    if not _enabled():
        return
    try:
        engagement = _engagement_id()
        if not engagement or not finding_id:
            return
        data = data or {}
        sev = str(data.get("severity") or "").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"
        finding = {"finding_id": str(finding_id), "title": str(data.get("title") or ""),
                   "severity": sev, "target": str(data.get("target") or ""),
                   "technique": data.get("technique"), "cve": data.get("cve") or None,
                   "proof_artifact_id": proof_artifact_id or None}
        finding = {k: v for k, v in finding.items() if v is not None}
        _EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        path = _EVENTS_DIR / f"{engagement}.jsonl"
        did = _current_decision.get(engagement)
        with _lock:
            env = _envelope("finding", engagement, _next_seq(engagement, path),
                            caused_by=[did] if did else None, correlation_id=did)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({**env, "finding": finding}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def emit_coverage_transition(cell: dict) -> None:
    """Emit a ``coverage_transition`` event when a matrix cell changes status (§3). A tested_clean is a
    genuine NEGATIVE label; a vulnerable closure links its finding. Fail-soft."""
    if not _enabled():
        return
    try:
        engagement = _engagement_id()
        if not engagement:
            return
        cell = cell or {}
        cid, status = str(cell.get("cell_id") or ""), str(cell.get("status") or "")
        if not cid or status not in ("pending", "in_progress", "tested_clean", "vulnerable", "not_applicable", "skipped"):
            return
        ct = {"cell_id": cid, "status": status}
        for k in ("endpoint_path", "method", "injection_type", "param_name", "finding_id", "artifact_id"):
            if cell.get(k):
                ct[k] = cell[k]
        _EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        path = _EVENTS_DIR / f"{engagement}.jsonl"
        with _lock:
            env = _envelope("coverage_transition", engagement, _next_seq(engagement, path))
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({**env, "coverage_transition": ct}, ensure_ascii=False) + "\n")
    except Exception:
        pass


def emit_tool_call(tool: str, ctx: dict, result: Any) -> None:
    """Emit one ``action`` event + the ``result`` it caused, linked to the current ``decision`` (if the
    agent recorded one). Fail-soft — never raises."""
    if not _enabled():
        return
    try:
        engagement = _engagement_id()
        if not engagement:
            return  # no active scan -> nothing to attribute the event to
        ctx = ctx or {}
        _EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        path = _EVENTS_DIR / f"{engagement}.jsonl"
        params = _params(ctx)
        fingerprint = "sha256:" + hashlib.sha256(
            json.dumps({"tool": tool, "params": params}, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        ev = getattr(result, "evidence", None) or {}
        did = _current_decision.get(engagement)  # the decision this action executes, if recorded
        with _lock:
            action = {**_envelope("action", engagement, _next_seq(engagement, path),
                                  caused_by=[did] if did else None, correlation_id=did),
                      "action": {"tool": tool,
                                 "operation": str(ctx.get("action") or ("exec" if ctx.get("command") else "call")),
                                 "params": params,
                                 "exact_action_hash": fingerprint,
                                 "semantic_action_family": _family(tool, ctx),
                                 "safety_class": _safety_class(tool, ctx)}}
            res = {**_envelope("result", engagement, _next_seq(engagement, path),
                               caused_by=[action["event_id"]], correlation_id=did),
                   "result": {"observed": {"execution_status": "error" if ev.get("error") else "ok",
                                           "result_class": _result_class(result)}}}
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(action, ensure_ascii=False) + "\n")
                f.write(json.dumps(res, ensure_ascii=False) + "\n")
    except Exception:
        pass  # fail-soft: instrumentation must never break the scan
