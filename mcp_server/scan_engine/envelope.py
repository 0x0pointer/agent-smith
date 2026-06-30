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

# Content-based dedup for QA alerts. Maps (code, message) → ISO timestamp last shown.
# Suppresses re-injection of an identical alert that Smith has already seen until
# either (a) the content changes, (b) the alert clears, or (c) the cooldown expires.
# Prevents Smith answering the same "553 cells lack tested_by" message every 120s.
_qa_alert_last_shown: dict[tuple, str] = {}
_QA_ALERT_DEDUP_SECONDS = 30 * 60  # 30 min cooldown per identical alert

import logging as _logging
_log = _logging.getLogger(__name__)


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


def _check_scan_gate(tool: str) -> str | None:
    """Return a blocking JSON string if this tool call should be short-circuited, else None.

    Checks (in order):
    1. Scan is paused for human intervention — all tools except session() blocked.
    2. Scan reached a terminal state — all tools except session() blocked.
    """
    if tool == "session":
        return None
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
    except (ImportError, AttributeError, OSError) as e:
        _log.warning("intervention check failed: %s", e)
    try:
        from core import session as _sess
        current = _sess.get() or {}
        scan_status = current.get("status", "")
        if scan_status in (
            "complete", "incomplete_with_unresolved_blockers", "limit_reached",
        ) and not current.get("triage_requested"):
            # A terminal scan normally blocks every tool but session(). The one
            # exception is an operator-triggered TRIAGE pass on a stopped scan:
            # while triage_requested is set, Smith must be able to call report()
            # (to record verdicts) and re-verify findings (http/kali) before the
            # gate slams shut again. The injected steering directive keeps the
            # pass scoped to adjudication; once every finding has a verdict the
            # flag clears (see /api/session self-heal) and this gate resumes
            # blocking all tools.
            return json.dumps({
                "status": "SCAN_COMPLETED",
                "scan_status": scan_status,
                "message": (
                    f"This scan has been marked '{scan_status}' by the human operator "
                    "via the dashboard (or a budget/time limit was reached). Stop "
                    "calling tools. Write one final brief summary message — "
                    "do NOT make any further tool calls — and end your turn."
                ),
                "how_to_resume": (
                    "If the human wants more testing they will start a fresh scan via "
                    "session(action='start') — do not call that yourself."
                ),
            }, indent=2)
    except (ImportError, AttributeError, OSError) as e:
        _log.warning("terminal-status check failed: %s", e)
    return None


def wrap(tool: str, raw_output: str, context: dict | None = None) -> str:
    """Central entry point: raw tool output in, canonical envelope JSON out.

    Args:
        tool: tool name (e.g. "httpx", "http_request", "kali_sqlmap")
        raw_output: the raw string output from the tool
        context: tool-specific context (url, method, params, etc.)

    Returns:
        JSON string of the canonical envelope
    """
    blocked = _check_scan_gate(tool)
    if blocked:
        return blocked

    ctx = context or {}

    # 1. Store raw output as artifact + remember it as the session's most-recent
    #    proof, so a finding filed right after auto-links it (adjudication can
    #    then reuse it instead of forcing a re-run).
    artifact_id = store_artifact(tool, raw_output)
    try:
        from core import session as _sess
        _sess.set_last_artifact(tool, artifact_id)
    except Exception:
        pass

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

    # 5.7b. Missing-Authorization warning. When an http_request returns 401/403
    # and the caller did NOT send an Authorization header, but known_assets has
    # at least one valid JWT, inject a high-pri warning telling Smith to retry
    # with the token. This catches the loop where Smith fires injection payloads
    # at /api/* without auth and accumulates 401s until HIR_AUTH_FAILURE fires.
    if tool == "http_request":
        _inject_missing_auth_warning(enforced, ctx)

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


def _update_jwt_tokens(scan_session: Any, req_headers: dict, body_prev: str, url: str) -> None:
    """Scan response body + auth-y request headers for JWT strings and persist any found."""
    from datetime import datetime, timezone
    haystack = body_prev
    for k, v in req_headers.items():
        if isinstance(v, str) and "auth" in k.lower():
            haystack += " " + v
    tokens = [
        {"type": "jwt", "value": m,
         "obtained_at": datetime.now(timezone.utc).isoformat(), "source_url": url}
        for m in _JWT_RE.findall(haystack)
    ]
    if tokens:
        scan_session.update_known_assets("auth_tokens", tokens)


def _update_credentials(
    scan_session: Any, url: str, method: str, status: int, req_body: str
) -> None:
    """Persist credentials and auth endpoint when a POST login succeeds."""
    import json
    if not (method == "POST" and 200 <= status < 300
            and any(h in url.lower() for h in _AUTH_PATH_HINTS) and req_body):
        return
    try:
        req_data = json.loads(req_body) if req_body.lstrip().startswith("{") else None
    except Exception:
        req_data = None
    if not isinstance(req_data, dict):
        return
    uname = req_data.get("username") or req_data.get("user") or req_data.get("email")
    pword = req_data.get("password") or req_data.get("pass") or req_data.get("pwd")
    if uname and pword:
        scan_session.update_known_assets("credentials", [{
            "username": str(uname), "password": str(pword),
            "source": f"login_success {url}",
        }])
        scan_session.update_known_assets("auth_endpoints", [{
            "path": url, "method": method,
            "body_template": {"username": "$USERNAME", "password": "$PASSWORD"},
        }])


def _persist_http_auth_assets(scan_session: Any, evidence: dict, ctx: dict) -> None:
    """Extract JWTs, credentials, and auth endpoints from an http_request.

    Triggers:
      - Any JWT-looking string in the response body or Authorization headers
        is added to known_assets.auth_tokens.
      - A 2xx response to POST to an auth-looking path whose request body
        contained username/password adds the credentials to known_assets.credentials
        AND registers the auth endpoint in known_assets.auth_endpoints.
    """
    status      = evidence.get("status", 0)
    body_prev   = evidence.get("body_preview", "")
    url         = ctx.get("url", "")
    method      = (ctx.get("method") or "GET").upper()
    req_body    = ctx.get("body", "") or ""
    req_headers = ctx.get("headers") or {}

    _update_jwt_tokens(scan_session, req_headers, body_prev, url)
    _update_credentials(scan_session, url, method, status, req_body)


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
    elif tool in ("fuzzyai", "garak", "pyrit", "promptfoo"):
        # AI scans pass the URL straight to the tool (no spider), so without this
        # the AI endpoint never lands in known_assets — leaving recovery and the
        # deepen gate blind to the AI surface. Persist the target path.
        target = ctx.get("target", "")
        if target:
            from urllib.parse import urlparse
            path = urlparse(target).path or target
            scan_session.update_known_assets("endpoints", [path])
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


# Headers commonly used by web apps to carry authentication. Authorization
# (JWT bearer / basic / digest), Cookie (session), and any X-*-Token /
# X-*-Auth / X-Api-Key / X-Access-Key variant most APIs adopt.
_AUTH_HEADER_NAMES_LOWER = ("authorization", "cookie", "x-csrf-token")
_AUTH_HEADER_PATTERNS = (
    "auth", "token", "api-key", "apikey", "access-key",
    "session", "credential", "bearer",
)
# Query-string params Smith may have used to embed a token.
_AUTH_QUERY_PATTERNS = ("token", "access_token", "api_key", "apikey", "auth", "session")


def _request_carries_auth(ctx: dict) -> bool:
    """True if the request sent SOME form of authentication.

    Generic across auth styles: JWT bearer, basic, cookies, custom X-* headers,
    or query-string tokens. If none of these are present the 401/403 is most
    likely caused by Smith forgetting auth entirely (vs sending an invalid one).
    """
    headers = ctx.get("headers") or {}
    for k in headers.keys():
        kl = k.lower()
        if kl in _AUTH_HEADER_NAMES_LOWER:
            return True
        if any(p in kl for p in _AUTH_HEADER_PATTERNS):
            return True
    # Query-string auth (e.g. ?token=..., ?access_token=...)
    url = ctx.get("url", "")
    if "?" in url:
        qs = url.split("?", 1)[1].lower()
        if any(f"{p}=" in qs for p in _AUTH_QUERY_PATTERNS):
            return True
    return False


def _inject_missing_auth_warning(env: Envelope, ctx: dict) -> None:
    """When an http_request gets 401/403 and Smith sent NO auth at all but
    valid JWTs/credentials exist in known_assets, prepend an actionable warning
    so Smith retries with the token on the next call.

    Skipped when:
      - response was not 401/403 (auth presumably worked or unrelated error)
      - the request carried any auth form (header, cookie, query token) —
        the token is invalid, not missing
      - this was a credential-validation attempt (login flow)
      - no JWT is yet available in known_assets
    """
    status = env.evidence.get("status", 0) if env.evidence else 0
    if status not in (401, 403):
        return
    if _request_carries_auth(ctx):
        return  # some auth WAS sent; the issue is the value, not absence
    if _is_auth_attempt(ctx):
        return  # legitimate login attempt — 401 is the test signal
    try:
        from core import session as _sess
        sess_data    = _sess.get() or {}
        known_assets = sess_data.get("known_assets", {})
        tokens       = known_assets.get("auth_tokens", [])
        valid_tokens = [t for t in tokens if isinstance(t, dict) and t.get("value")]
        if not valid_tokens:
            return
        url    = ctx.get("url", "")
        method = (ctx.get("method", "GET") or "GET").upper()

        # Smaller models (the user hit this with Qwen3.6-35B-A3B) treat
        # short "try header X" warnings as background noise and burn 7+
        # tool calls retrying naked requests against the same endpoint.
        # The fix is the same shape we used for the envelope budget
        # truncation: embed the EXACT next tool call inline with the
        # full token-reference path. The model can pattern-match on
        # `EXECUTE NOW: http(...)` far more reliably than on a discursive
        # "you should try X, or maybe Y" paragraph.
        #
        # The token reference is `known_assets.auth_tokens[-1].value`
        # (not a truncated literal) because:
        #   1. Models that DO read warnings can resolve the path from
        #      session state directly without us inlining a 700-char JWT
        #      that would blow the envelope budget.
        #   2. The truncated form `eyJ0eXAiOiJK...` previously shown
        #      reads like a complete token to less-careful models, which
        #      then sent the truncated value verbatim and got 401 again.
        creds = known_assets.get("credentials", [])
        auth_endpoints = known_assets.get("auth_endpoints", [])
        cred_hint = ""
        if creds and auth_endpoints:
            ep = auth_endpoints[0]
            cred_hint = (
                f" If the stored token has expired (still 401 after the "
                f"retry above), mint a fresh one: "
                f"http(action='request', method='{ep.get('method','POST')}', "
                f"url='{ep.get('path','')}', "
                f"body={{'username':'{creds[0].get('username','')}', "
                f"'password':'{creds[0].get('password','')}'}}). "
                f"Extract the new JWT from the response and retry."
            )
        message = (
            f"AUTH_MISSING: {method} {url} returned HTTP {status} with NO auth "
            f"attached (no Authorization / Cookie / X-Api-Key / X-Auth-* / "
            f"?token= query). 401/403 with no auth is NOT a test result — "
            f"the server never evaluated your payload. "
            f"EXECUTE NOW: retry the same request with the JWT attached: "
            f"http(action='request', method='{method}', url='{url}', "
            f"headers={{'Authorization': 'Bearer ' + "
            f"known_assets.auth_tokens[-1].value}}). "
            f"({len(valid_tokens)} valid token(s) available; "
            f"newest source: {valid_tokens[-1].get('source_url','unknown')}). "
            f"If 401 persists, the app may use Cookie auth (re-login + reuse "
            f"Set-Cookie) or a custom header like X-Api-Key/X-Auth-Token — try "
            f"those header names with the same JWT value."
            f"{cred_hint}"
            f" DO NOT retry the naked request — every naked retry will return "
            f"401 and burns budget without producing a test result."
        )
        env.warnings.append(message)
        env.summary = f"⚠ {message}\n\n" + env.summary
    except Exception:
        pass  # never break tool dispatch


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

    Dedup strategy:
      1. Timestamp gate: skip the whole qa_state.json tick if its `ts` hasn't moved.
      2. Per-alert content dedup: even within a fresh tick, suppress any alert
         whose (code, message) was already shown within _QA_ALERT_DEDUP_SECONDS.
         This stops Smith answering the same "X cells lack tested_by" message
         every 120s. Cooldown resets when the message content changes.
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

        # Per-alert content dedup
        fresh = _filter_qa_alerts_by_dedup(high, ts)
        if not fresh:
            return  # everything is stale-dup; no point injecting

        for a in fresh:
            env.warnings.append(f"[QA HIGH] {a['message']}")

        if not suppress_summary_prepend:
            alert_text = " | ".join(a["message"] for a in fresh)
            env.summary = (
                f"⚠ QA ALERT: {alert_text}\n"
                f"(Address before continuing or call session(action='status') to review.)\n\n"
                + env.summary
            )
    except Exception:
        pass  # never break tool dispatch


def _filter_qa_alerts_by_dedup(alerts: list[dict], current_ts: str) -> list[dict]:
    """Return only alerts not shown within the cooldown window.

    Fingerprint = (code, message). When the message text changes (e.g. count
    grew from 553 to 612 cells), the fingerprint changes too and the alert
    re-fires. Identical repeats are suppressed for _QA_ALERT_DEDUP_SECONDS.
    """
    from datetime import datetime, timezone
    try:
        now_dt = datetime.fromisoformat(current_ts.replace("Z", "+00:00"))
    except Exception:
        # Falls back to no dedup if we can't parse the timestamp.
        return alerts

    fresh: list[dict] = []
    for a in alerts:
        fp = (a.get("code", ""), a.get("message", ""))
        last = _qa_alert_last_shown.get(fp)
        if last:
            try:
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                if (now_dt - last_dt).total_seconds() < _QA_ALERT_DEDUP_SECONDS:
                    continue  # dedup
            except Exception:
                pass
        fresh.append(a)
        _qa_alert_last_shown[fp] = current_ts
    return fresh


# ---------------------------------------------------------------------------
# P6 — Quick log
# ---------------------------------------------------------------------------

# Field names that mark a request body / form / query as a credential-
# validation attempt. Matched generically — no endpoint-name allowlist.
_AUTH_PAYLOAD_FIELDS = (
    "password", "passwd", "pwd", "pass",
    "secret", "client_secret",
    "api_key", "apikey", "access_token", "refresh_token", "id_token",
    "credential", "credentials",
    "otp", "totp", "mfa_code", "code",
)
_AUTH_FIELD_RE = __import__("re").compile(
    r'["\']?(' + "|".join(_AUTH_PAYLOAD_FIELDS) + r')["\']?\s*[:=]',
    __import__("re").IGNORECASE,
)


def _is_zero_status(raw: Any) -> bool:
    """Return True if `raw` represents HTTP status 0 — i.e. no response was
    received (aiohttp/requests exception path).

    Accepts both numeric 0 and the string "0" so we don't silently miss a
    status that was serialized through a JSON round-trip. Anything else
    (including None, malformed strings, real status codes) returns False.
    """
    if raw == 0:
        return True
    if isinstance(raw, str) and raw.strip() == "0":
        return True
    return False


def _is_auth_attempt(ctx: dict) -> bool:
    """True if this http_request looks like a credential validation attempt.

    Generic signals — no URL allowlist, works for any app's naming:
      1. The request body / form / query contains a field name from
         _AUTH_PAYLOAD_FIELDS (password, secret, api_key, otp, ...).
      2. The request URL exactly matches a known auth endpoint discovered
         earlier in the scan (known_assets.auth_endpoints).
    """
    body  = (ctx.get("body") or "")
    query = (ctx.get("query") or "")
    haystack = body + " " + query
    # Auth-bearing request headers should NOT trigger this (we're sending auth, not testing it)
    if _AUTH_FIELD_RE.search(haystack):
        return True
    try:
        from core import session as _sess
        ka = (_sess.get() or {}).get("known_assets", {})
        url = ctx.get("url", "")
        for ep in ka.get("auth_endpoints", []):
            if isinstance(ep, dict) and ep.get("path") and ep["path"] in url:
                return True
    except Exception:
        pass
    return False


def _build_quick_log_entry(
    tool: str, target: str, summarizer_summary: str, result: Any, ctx: dict | None = None,
) -> dict:
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
    _enrich_http_request_entry(entry, tool, result, ctx)
    _mark_tool_error(entry, tool, result)
    return entry


def _enrich_http_request_entry(
    entry: dict, tool: str, result: Any, ctx: dict | None
) -> None:
    """Add status_code and auth_attempt fields to http_request log entries."""
    if result is None or tool != "http_request":
        return
    ev = result.evidence or {}
    sc = ev.get("status", 0)
    if sc:
        entry["status_code"] = int(sc)
    if ctx and _is_auth_attempt(ctx):
        entry["auth_attempt"] = True


def _mark_tool_error(entry: dict, tool: str, result: Any) -> None:
    """Set entry["error"] = True when the tool call itself produced no real response.

    Only two narrow signals qualify (see _build_quick_log_entry for rationale).
    """
    if result is None:
        return
    ev = result.evidence or {}
    if ev.get("error") or (tool == "http_request" and _is_zero_status(ev.get("status"))):
        entry["error"] = True


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
        entry = _build_quick_log_entry(tool, target, summarizer_summary, result, ctx)
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
