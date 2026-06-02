"""
Canonical response envelope — every tool returns this exact shape.

The envelope is the only thing that enters the LLM context window.
Raw output lives in artifacts, referenced by artifact_id.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field, asdict
from typing import Any, TYPE_CHECKING

from mcp_server.scan_engine.artifacts import store_artifact
from mcp_server.scan_engine.budget import enforce_budget, get_tool_budget, get_profile
from mcp_server.scan_engine.planner import compute_next
from mcp_server.scan_engine.state import get_state
from mcp_server.scan_engine.summarizers import summarize

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
_QA_STATE_FILE      = _REPO_ROOT / "qa_state.json"
_STEERING_FILE      = _REPO_ROOT / "steering_queue.json"
_RECOVERY_SNAP_FILE = _REPO_ROOT / "recovery_latest.json"
_last_qa_shown_ts: str = ""  # ISO timestamp of last alert batch shown to the model


@dataclass
class Envelope:
    summary: str = ""
    facts: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    next: dict[str, list[str]] = field(default_factory=lambda: {"required": [], "recommended": []})
    artifact: str | None = None
    session_state: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def wrap(tool: str, raw_output: str, context: dict | None = None) -> str:
    """Central entry point: raw tool output in, canonical envelope JSON out.

    Args:
        tool: tool name (e.g. "httpx", "http_request", "kali_sqlmap")
        raw_output: the raw string output from the tool
        context: tool-specific context (url, method, params, etc.)

    Returns:
        JSON string of the canonical envelope
    """
    # Block all tool calls while scan is paused for human intervention.
    # session() calls are exempt so the agent can call session(action='resume').
    if tool != "session":
        try:
            from core import session as _sess
            iv = _sess.get_intervention()
            if iv:
                return json.dumps({
                    "status": "HUMAN_INTERVENTION_REQUIRED",
                    "code":   iv.get("code", "HIR_UNKNOWN"),
                    "situation": iv.get("situation", ""),
                    "options":   iv.get("options", []),
                    "scan_paused": True,
                    "how_to_respond": (
                        "The scan is paused. Respond via the dashboard 'Send to Smith' panel, "
                        "or call: session(action='resume', options={choice: '...', message: '...'})"
                    ),
                }, indent=2)
        except Exception:
            pass

    ctx = context or {}

    # 1. Store raw output as artifact
    artifact_id = store_artifact(tool, raw_output)

    # 2. Run tool-specific summarizer
    result = summarize(tool, raw_output, ctx)

    # 2a. Record tool invocation with summary (P1 — dedup + recovery)
    is_duplicate = _record_invocation(tool, ctx, result.summary)

    # 2b. Extract and persist known assets (P2 — auto-accumulation)
    _extract_and_persist_assets(tool, result, ctx)

    # 3. Compute server-determined state and planner next-actions
    state = get_state()
    plan = compute_next(tool, state)

    # Merge: planner required/recommended take priority, summarizer adds tool-specific ones
    merged_required = plan["required"] + result.required
    # Cap recommended to 3 — Smith acts on item 1, rarely on 2-3, never on 4+
    merged_recommended = (plan["recommended"] + result.recommended)[:3]
    warnings = plan["warnings"]

    # Cap facts to 5 — full detail lives in the artifact; facts are orientation only
    capped_facts = result.facts[:5]

    # 4. Build envelope — prepend first required action to summary so models see it
    summary = result.summary
    if merged_required:
        # Skip planner "Start scan" directives if session is already running
        actionable = [r for r in merged_required if not r.startswith("Start scan:")]
        if actionable:
            summary += f"\n\nEXECUTE NEXT: {actionable[0]}"
            if len(actionable) > 1:
                summary += f"\n(then {len(actionable) - 1} more required action(s) in next.required)"

    env = Envelope(
        summary=summary,
        facts=capped_facts,
        anomalies=result.anomalies,
        evidence=result.evidence,
        next={"required": merged_required, "recommended": merged_recommended},
        artifact=artifact_id,
        session_state=_compact_state(state),
        warnings=warnings,
    )

    # 5. Enforce budget (profile-aware) — may truncate facts/evidence
    budget = get_tool_budget(tool)
    enforced = enforce_budget(env, budget, artifact_id)

    # 5.5. Steering directives — inject first; return value suppresses QA summary prepend
    directive_injected = _inject_steering_directives(enforced)

    # 5.6. QA alerts — high urgency only; skip summary prepend when directive already owns it
    _inject_qa_alerts_into_envelope(enforced, suppress_summary_prepend=directive_injected)

    # 5.7. Duplicate tool call warning
    if is_duplicate:
        _inject_duplicate_warning(enforced, tool)

    # 5.8. Quick log — fire-and-forget, does not block
    _quick_log_tool(tool, ctx, result.summary, result)

    # 6. Context tracking (P4) — charge, check pressure tiers, periodic snapshot
    json_str = enforced.to_json()
    json_str = _check_context_pressure(enforced, json_str)

    return json_str


# ---------------------------------------------------------------------------
# P1 — Tool invocation recording
# ---------------------------------------------------------------------------

def _record_invocation(tool: str, ctx: dict, summary: str) -> bool:
    """Record tool invocation with summary for dedup and recovery.

    Returns True if this invocation was a duplicate (same tool+target+options already seen).
    """
    import hashlib
    from core import session as scan_session
    target = ctx.get("url", ctx.get("host", ctx.get("domain", ctx.get("path", ""))))
    hash_input = f"{tool}:{target}:{sorted(ctx.items())}"
    options_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    current = scan_session.get() or {}
    invocations = current.get("tool_invocations", [])
    is_duplicate = bool(options_hash and any(i.get("options_hash") == options_hash for i in invocations))
    scan_session.add_tool_invocation(tool, target, summary, options_hash)
    return is_duplicate


# ---------------------------------------------------------------------------
# P2 — Known assets extraction
# ---------------------------------------------------------------------------

def _persist_httpx_assets(scan_session: Any, evidence: dict) -> None:
    """Persist tech stack and server assets from httpx evidence."""
    tech = evidence.get("tech", [])
    if tech:
        scan_session.update_known_assets(
            "technologies", tech if isinstance(tech, list) else [tech])
    server = evidence.get("server")
    if server:
        scan_session.update_known_assets("technologies", [server])


def _persist_port_scan_assets(scan_session: Any, evidence: dict, ctx: dict) -> None:
    """Persist ports and hosts from naabu/nmap evidence."""
    ports = evidence.get("ports", [])
    hosts = evidence.get("hosts", [])
    host = hosts[0] if hosts else ctx.get("host", "")
    if ports:
        scan_session.update_known_assets(
            "ports", [{"host": host, "port": p} for p in ports])
    if hosts:
        scan_session.update_known_assets("domains", hosts)


_JWT_RE = __import__("re").compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+")
_AUTH_PATH_HINTS = ("login", "signin", "auth", "token", "session")


def _persist_http_auth_assets(scan_session: Any, evidence: dict, ctx: dict) -> None:
    """Extract JWTs, credentials, and auth endpoints from an http_request.

    Triggers:
      - Any JWT-looking string in the response body or Authorization headers
        is added to known_assets.auth_tokens.
      - A 2xx response to POST to an auth-looking path whose request body
        contained username/password adds the credentials to known_assets.credentials
        AND registers the auth endpoint in known_assets.auth_endpoints.
    """
    import json
    from datetime import datetime, timezone

    status     = evidence.get("status", 0)
    body_prev  = evidence.get("body_preview", "")
    url        = ctx.get("url", "")
    method     = (ctx.get("method") or "GET").upper()
    req_body   = ctx.get("body", "") or ""
    req_headers = ctx.get("headers") or {}

    # 1. JWT extraction — search response body and any Authorization-like input
    haystack = body_prev
    for k, v in req_headers.items():
        if isinstance(v, str) and "auth" in k.lower():
            haystack += " " + v
    tokens = []
    for m in _JWT_RE.findall(haystack):
        tokens.append({
            "type":        "jwt",
            "value":       m,
            "obtained_at": datetime.now(timezone.utc).isoformat(),
            "source_url":  url,
        })
    if tokens:
        scan_session.update_known_assets("auth_tokens", tokens)

    # 2. Credential + auth_endpoint extraction — POST to auth-y path with 2xx
    path_lower = url.lower()
    is_auth_path = any(h in path_lower for h in _AUTH_PATH_HINTS)
    if method == "POST" and 200 <= status < 300 and is_auth_path and req_body:
        try:
            req_data = json.loads(req_body) if req_body.lstrip().startswith("{") else None
        except Exception:
            req_data = None
        if isinstance(req_data, dict):
            uname = req_data.get("username") or req_data.get("user") or req_data.get("email")
            pword = req_data.get("password") or req_data.get("pass") or req_data.get("pwd")
            if uname and pword:
                scan_session.update_known_assets("credentials", [{
                    "username": str(uname),
                    "password": str(pword),
                    "source":   f"login_success {url}",
                }])
                scan_session.update_known_assets("auth_endpoints", [{
                    "path":         url,
                    "method":       method,
                    "body_template": {"username": "$USERNAME", "password": "$PASSWORD"},
                }])


def _extract_and_persist_assets(tool: str, result: Any, ctx: dict) -> None:
    """Extract discovered assets from summarizer result and persist to session."""
    from core import session as scan_session
    evidence = result.evidence

    if tool == "httpx":
        _persist_httpx_assets(scan_session, evidence)
    elif tool in ("naabu", "nmap"):
        _persist_port_scan_assets(scan_session, evidence, ctx)
    elif tool == "subfinder":
        subs = evidence.get("subdomains", [])
        if subs:
            scan_session.update_known_assets("domains", subs[:50])
    elif tool == "spider":
        endpoints = evidence.get("endpoints", [])
        if endpoints:
            scan_session.update_known_assets(
                "endpoints",
                [ep.get("path", "") for ep in endpoints if ep.get("path")])
    elif tool == "http_request":
        _persist_http_auth_assets(scan_session, evidence, ctx)


# ---------------------------------------------------------------------------
# P4 — Context pressure tracking (tiered)
# ---------------------------------------------------------------------------

def _check_context_pressure(env: Envelope, json_str: str) -> str:
    """Track context usage and inject tiered warnings as pressure grows.

    Tier 1 (>70%): advisory — good time to call recovery.
    Tier 2 (>80%): urgent — EXECUTE NOW directive with exact call.
    Tier 3 (>90%): auto-inject full recovery brief into session_state; no model action needed.
    Also writes a periodic snapshot to recovery_latest.json every 10 tool calls.
    """
    from core import session as scan_session
    scan_session.charge_context(len(json_str))
    profile = get_profile()
    pressure = scan_session.get_context_pressure(profile)

    _maybe_write_recovery_snapshot(scan_session)

    if pressure > 0.9:
        pct = int(pressure * 100)
        env.warnings.append(
            f"CONTEXT_WARNING: ~{pct}% of context budget used — compaction imminent. "
            f"Recovery brief auto-injected into session_state.recovery_brief. "
            f"EXECUTE NOW: session(action='recovery') for a fresh copy."
        )
        try:
            from mcp_server.session_tools import _do_recovery
            import json as _json
            env.session_state["recovery_brief"] = _json.loads(_do_recovery())
        except Exception:
            pass
        return env.to_json()

    if pressure > 0.8:
        pct = int(pressure * 100)
        env.warnings.append(
            f"CONTEXT_WARNING: ~{pct}% of context budget used. "
            f"EXECUTE NOW: session(action='recovery') — all state is safe on disk. "
            f"After reading the brief, continue from its EXECUTE_NOW field."
        )
        return env.to_json()

    if pressure > 0.7:
        pct = int(pressure * 100)
        env.warnings.append(
            f"CONTEXT_WARNING: ~{pct}% of context budget used. "
            f"Good time to call session(action='recovery') to get a compact state snapshot."
        )
        return env.to_json()

    return json_str


def _maybe_write_recovery_snapshot(scan_session: Any) -> None:
    """Write recovery_latest.json periodically as a structured, executable checkpoint.

    Frequency: every 10 calls (standard) / every 20 calls (thorough) based on depth.
    The checkpoint includes an executable EXECUTE_NOW so post-compaction resume is 1 call.
    """
    try:
        current = scan_session.get() or {}
        if current.get("status") != "running":
            return
        seq = len(current.get("tool_invocations", []))
        if seq == 0:
            return
        interval = 20 if current.get("depth") == "thorough" else 10
        if seq % interval != 0:
            return
        from mcp_server.session_tools import _do_recovery
        from core.coverage import get_matrix
        snap = _RECOVERY_SNAP_FILE.resolve()
        if _REPO_ROOT.resolve() not in snap.parents:
            return

        # Build structured checkpoint enriched with coverage state
        recovery = json.loads(_do_recovery())
        cov = get_matrix()
        meta = cov.get("meta", {})
        ep_map = {ep["id"]: ep["path"] for ep in cov.get("endpoints", [])}

        # Top 5 pending cells by injection priority for the checkpoint
        priority_order = ["sqli", "xss", "ssti", "cmdi", "ssrf", "idor"]
        pending = [c for c in cov.get("matrix", []) if c["status"] in ("pending", "in_progress")]
        pending.sort(key=lambda c: (
            priority_order.index(c["injection_type"]) if c["injection_type"] in priority_order else 99,
            0 if c["status"] == "in_progress" else 1,
        ))
        recovery["checkpoint"] = {
            "seq":           seq,
            "ts":            __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "depth":         current.get("depth", ""),
            "phase":         current.get("phase", ""),
            "active_skill":  current.get("skill", ""),
            "coverage":      f"{meta.get('tested', 0)}/{meta.get('total_cells', 0)}",
            "top_pending":   [
                {
                    "cell_id":   c["id"],
                    "endpoint":  ep_map.get(c["endpoint_id"], "?"),
                    "param":     c["param"],
                    "injection": c["injection_type"],
                    "status":    c["status"],
                }
                for c in pending[:5]
            ],
        }
        snap.write_text(json.dumps(recovery, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# P5.6 — Steering directive injection
# ---------------------------------------------------------------------------

def _inject_steering_directives(env: Envelope) -> bool:
    """Inject pending QA steering directives into the envelope.

    High-priority directives are prepended to the summary so the model sees them
    immediately. All directives appear in warnings for the audit trail.
    Each directive is marked injected after surfacing.

    Returns True if any directive was injected (used to suppress QA alert prepend).
    """
    try:
        from core.steering import steering_queue
        pending = steering_queue.get_pending()
        injected = False
        for directive in pending:
            env.warnings.append(f"[QA STEER {directive.priority.upper()}] {directive.message}")
            if directive.priority == "high":
                is_human = directive.trigger == "HUMAN_STEER"
                ack_reminder = (
                    "REPLY TO THE HUMAN NOW so they see your response on the dashboard: "
                    "call session(action='qa_reply', options={message: '<your reply>'}). "
                    "Without this call your terminal output never reaches the human."
                ) if is_human else (
                    "Acknowledge with session(action='qa_reply', options={message: '<your reply>'}) "
                    "after acting on this directive."
                )
                env.summary = (
                    f"⚠ QA STEERING: {directive.message}\n"
                    f"(Act on this before continuing. {ack_reminder})\n\n"
                    + env.summary
                )
            steering_queue.mark_injected(directive.id)
            injected = True

        # Nag mode: even after a directive is "injected", keep reminding Smith
        # about unacknowledged HUMAN_STEER messages on every tool call until
        # it actually calls qa_reply. Otherwise Smith reads the reminder once,
        # acts on the substance, and the human never sees a reply.
        active = steering_queue.get_active()  # pending + injected
        unanswered_human = [
            d for d in active
            if d.trigger == "HUMAN_STEER" and d.status == "injected"
        ]
        if unanswered_human and not injected:
            messages = "; ".join(f'"{d.message[:120]}"' for d in unanswered_human)
            env.warnings.append(
                f"UNANSWERED HUMAN STEER ({len(unanswered_human)}): {messages}"
            )
            env.summary = (
                f"⚠ UNANSWERED HUMAN STEER ({len(unanswered_human)}): "
                f"the human is waiting for a reply. "
                f"CALL NOW: session(action='qa_reply', options={{message: '<your reply>'}}). "
                f"Pending: {messages}\n\n"
                + env.summary
            )
            injected = True

        return injected
    except Exception:
        return False  # steering failures must never break tool dispatch


def _inject_duplicate_warning(env: Envelope, tool: str) -> None:
    """Inject a recovery reminder when the same tool+params were already run."""
    from core import session as scan_session
    try:
        invocations = (scan_session.get() or {}).get("tool_invocations", [])
        seq = next(
            (i.get("seq") for i in reversed(invocations) if i.get("tool") == tool),
            "?",
        )
        env.warnings.append(
            f"DUPLICATE_TOOL_CALL: {tool} was already run with these exact parameters "
            f"(invocation #{seq}). You may be post-compaction. "
            "Call session(action='recovery') to verify where you left off."
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# P5 — QA alert injection
# ---------------------------------------------------------------------------

def _inject_qa_alerts_into_envelope(env: Envelope, suppress_summary_prepend: bool = False) -> None:
    """Read qa_state.json and inject high-urgency alerts into the envelope.

    High urgency  → appended to env.warnings AND (unless suppressed) prepended to
                    env.summary. Summary prepend is suppressed when a steering directive
                    already owns that slot — one ⚠ header at a time.
    Medium urgency → skipped (dashboard-only; not model-facing).
    Low urgency   → skipped (dashboard-only; not model-facing).

    Uses a module-level timestamp so each alert is shown exactly once across
    consecutive tool calls, not repeated on every response.
    """
    global _last_qa_shown_ts
    try:
        if not _QA_STATE_FILE.is_file():
            return
        state = json.loads(_QA_STATE_FILE.read_text(encoding="utf-8"))
        ts = state.get("ts", "")
        if not ts or ts <= _last_qa_shown_ts:
            return
        high = [a for a in state.get("alerts", []) if a.get("urgency") == "high"]
        if not high:
            _last_qa_shown_ts = ts
            return
        _last_qa_shown_ts = ts

        for a in high:
            env.warnings.append(f"[QA HIGH] {a['message']}")

        if not suppress_summary_prepend:
            alert_text = " | ".join(a["message"] for a in high)
            env.summary = (
                f"⚠ QA ALERT: {alert_text}\n"
                f"(Address before continuing or call session(action='status') to review.)\n\n"
                + env.summary
            )
    except Exception:
        pass  # never break tool dispatch


# ---------------------------------------------------------------------------
# P6 — Quick log
# ---------------------------------------------------------------------------

def _build_quick_log_entry(tool: str, target: str, summarizer_summary: str, result: Any) -> dict:
    """Build and return the quick_log entry dict for a tool call.

    Handles the spider vs TOOL branching, status_code extraction, and error
    detection. Extracted from _quick_log_tool to reduce cognitive complexity.
    """
    import re as _re
    if tool == "spider":
        m = _re.search(r'(\d+)\s+unique\s+endpoint', summarizer_summary, _re.IGNORECASE)
        return {
            "type": "SPIDER",
            "target": target,
            "endpoints_found": int(m.group(1)) if m else 0,
        }

    entry: dict = {"type": "TOOL", "name": tool, "target": target}
    # Enrich http_request entries with status_code for auth failure detection
    if result is not None and tool == "http_request":
        ev = result.evidence or {}
        sc = ev.get("status", 0)
        if sc:
            entry["status_code"] = int(sc)
    # Mark failed tool calls so QA can detect unreachable targets / repeated failures
    if result is not None:
        ev = result.evidence or {}
        is_error = bool(
            ev.get("error")
            or (tool == "http_request" and int(ev.get("status", 200) or 200) == 0)
            or (result.anomalies and any("error" in str(a).lower() or "timeout" in str(a).lower() or "unreachable" in str(a).lower() for a in result.anomalies))
        )
        if is_error:
            entry["error"] = True
    return entry


def _quick_log_tool(tool: str, ctx: dict, summarizer_summary: str, result: Any = None) -> None:
    """Fire-and-forget quick_log entry. Called from within an async tool handler
    so asyncio.get_running_loop() is always available.

    Uses the summarizer's summary (before QA injection) so the log reflects
    what the tool actually found, not the alert state.

    status_code and error fields are extracted from result.evidence when available
    so the QA daemon can detect auth failures, unreachable targets, and tool failures.
    """
    import asyncio
    try:
        from core.quick_log import quick_log as _qlog
        target = ctx.get("url", ctx.get("host", ctx.get("domain", ctx.get("path", ""))))
        entry = _build_quick_log_entry(tool, target, summarizer_summary, result)
        loop = asyncio.get_running_loop()
        loop.create_task(_qlog.append(entry))
    except Exception:
        pass  # quick_log failures must never affect tool dispatch


# ---------------------------------------------------------------------------
# State compaction — strip fields the model doesn't need on every response
# ---------------------------------------------------------------------------

def _compact_state(state: dict) -> dict:
    """Return a fingerprint of scan state for embedding in the envelope.

    Drops `tools_run` (grows unboundedly, not useful per-response) and
    `time_pct` (low-value scalar). Anything Smith needs beyond this is one
    session(action='status') call away.
    """
    keep = ("target", "phase", "active_skill", "coverage", "findings",
            "calls_used", "pending_escalations", "in_progress_cells")
    return {k: state[k] for k in keep if k in state}
