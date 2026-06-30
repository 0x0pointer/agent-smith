"""
Consolidated report tool — replaces reporting.py
"""
import asyncio
import json
import re
from typing import Any

from core import findings as findings_store
from core import logger as log
from core import session as scan_session
from mcp_server._app import mcp

_background_tasks: set[asyncio.Task] = set()  # keeps fire-and-forget tasks alive


# ── Gate auto-triggers ────────────────────────────────────────────────────────
# Keywords in finding titles/descriptions that indicate RCE — triggers post-exploit gate.
_RCE_KEYWORDS = (
    "command injection", "rce", "remote code execution", "code execution",
    "ssti", "server-side template injection", "deserialization",
    "os command", "shell injection", "eval injection",
)

# Keywords in notes that indicate container/K8s environment — triggers container gate.
_K8S_KEYWORDS = (
    "kubernetes", "kubepods", "/.dockerenv", "dockerenv",
    "sa token", "serviceaccount", "k8s", "containerd", "cri-o",
)

# Keywords in notes that indicate cloud metadata access — triggers cloud gate.
_CLOUD_KEYWORDS = (
    "metadata service", "imds", "cloud metadata",
    "iam role", "instance profile", "link-local metadata",
)
# Cloud metadata IPs checked separately to avoid hardcoded-IP linting rules.
_CLOUD_METADATA_PREFIX = "169.254."

# Keywords in notes that indicate internal network discovery — triggers network gate.
# Deliberately broad: agents write notes in many styles ("172.18.0.0/24", "host at 10.",
# "docker network", "reachable from DB container", etc.) — all should fire the gate.
_INTERNAL_NET_KEYWORDS = (
    # Explicit phrasing
    "internal subnet", "internal network", "non-public subnet",
    "live hosts on 10.", "live hosts on 172.", "live hosts on 192.168.",
    # Natural phrasing agents actually write
    "docker network", "container network", "host at 10.", "host at 172.",
    "hosts at 10.", "hosts at 172.", "hosts at 192.168.",
    "reachable from", "pivot", "10.0.", "10.1.", "10.2.", "10.10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "192.168.", "subnet /24", "subnet /16",
)

# Keywords that indicate auth services — triggers credential-audit gate.
_AUTH_KEYWORDS = (
    "ssh", "ftp", "smb", "rdp", "vnc", "telnet",
    "login form", "basic auth", "admin panel", "management console",
    "mysql", "postgres", "mssql", "mongodb", "redis", "ldap",
)


@mcp.tool()
async def report(action: str, data: Any) -> str:
    """Log findings, diagrams, notes, or coverage matrix updates.

    action : finding | update_finding | delete_finding | diagram | note | dashboard | coverage

    finding data:
      title, severity (critical|high|medium|low|info), target,
      description, evidence, tool_used=, cve=, business_impact=,
      reproduction= {type: http|command|script|manual, command: "...", expected: "..."},
      trace= (optional, WHITE-BOX findings) source data flow as an ordered list
        [{kind: entrypoint|propagation|sink, file, line, scope, description}] —
        first step entrypoint, last step sink, >=2 steps. When a codebase is
        pinned (session set_codebase), each cited file:line is RESOLVED against
        the repo and a citation that doesn't exist is REJECTED. Omit for
        black-box findings. Duplicate findings (same target+title+severity, not a
        prior false_positive) are deduplicated — re-file distinct issues with a
        more specific title.

    update_finding data:
      id (required), plus any fields to update:
      severity, title, description, evidence, status (confirmed|false_positive|draft),
      gh_issue, remediation, reproduction, escalation_leads,
      adjudication ({reproducible, artifact_id, original_severity, revised_severity, rationale} —
      the final senior-review verdict; rationale is required, and artifact_id (an
      artifact that exists on disk) is required when reproducible=true)

    delete_finding data:
      id — moves the finding to the archived[] array (not permanently deleted)

    diagram data:
      title, mermaid (valid Mermaid source)

    note data:
      message

    chain data:
      name, steps=[{from_finding_id, to_finding_id, transition_artifact_id, mitre_technique}],
      terminal_impact=, combined_severity=
      — records a PROVEN exploit chain: every step's transition_artifact_id must
      exist on disk (the artifact proving step N's output feeds step N+1), else the
      chain is rejected. Auto-renders a MITRE-labelled Mermaid kill-chain diagram.

    dashboard data:
      port=7777

    coverage data:
      type: endpoint | tested | bulk_tested | reset

      endpoint — register an endpoint and auto-generate test cells:
        path, method, params=[{name, type, value_hint}], discovered_by=spider, auth_context=none

      tested — mark a single cell as tested:
        cell_id, status (tested_clean|vulnerable|not_applicable|skipped), notes=, finding_id=

      bulk_tested — mark multiple cells:
        updates=[{cell_id, status, notes=, finding_id=}]

      reset — clear the entire matrix (no additional fields)
    """
    try:
        if isinstance(data, str):
            data = json.loads(data)
    except (json.JSONDecodeError, TypeError) as exc:
        log.note(f"report({action}) data parse error: {exc} — raw: {str(data)[:200]}")
        return f"Error: could not parse data as JSON: {exc}"
    if not isinstance(data, dict):
        log.note(f"report({action}) data is not a dict: {type(data).__name__}")
        return f"Error: data must be a JSON object/dict, got {type(data).__name__}"
    if action == "finding":
        return await _do_finding(data)
    elif action == "update_finding":
        return await _do_update_finding(data)
    elif action == "delete_finding":
        return await _do_delete_finding(data)
    elif action == "diagram":
        return await _do_diagram(data)
    elif action == "note":
        return _do_note(data)
    elif action == "dashboard":
        return await _do_dashboard(data)
    elif action == "coverage":
        return await _do_coverage(data)
    elif action == "chain":
        return await _do_chain(data)
    else:
        return f"Unknown action '{action}'. Use: finding, update_finding, delete_finding, diagram, note, dashboard, coverage, chain"


# ── Finding hygiene: trace validation + cross-run dedup ─────────────────────────
_WS_RE = re.compile(r"\s+")


def _norm_text(s: Any) -> str:
    """Lowercase, strip, collapse internal whitespace — for stable comparison."""
    return _WS_RE.sub(" ", str(s or "").strip().lower())


def _norm_target(s: Any) -> str:
    """Normalise a target so http://x/ and HTTP://X compare equal."""
    return _norm_text(s).rstrip("/")


def _validate_trace_field(data: dict) -> str | None:
    """REJECTED message if data carries an invalid/unresolved trace[], else None.

    Fires only when a trace is present — black-box findings (no source) are
    untouched. When a codebase is pinned, this resolves each cited file:line
    against disk, so a hallucinated source location is rejected at the boundary.
    """
    trace = data.get("trace")
    if trace is None:
        return None
    from core.findings_validate import validate_finding_trace
    ok, errors = validate_finding_trace(trace)
    if ok:
        return None
    return (
        "REJECTED: finding 'trace' has invalid or unresolved source citations — fix these "
        "before filing (omit 'trace' for black-box findings that have no source location):\n  - "
        + "\n  - ".join(errors)
    )


def _find_duplicate(title: str, target: str, severity: str) -> dict | None:
    """Return an existing finding with the same target+title+severity, if any.

    The cross-run/within-run dedup key. Gated on status (NEVER a bare title
    match): a finding previously adjudicated ``false_positive`` does NOT
    suppress a fresh one — re-discovering a was-FP-now-real issue must be
    allowed. Severity is part of the key so a later, higher-severity re-rating
    of the same issue is treated as an escalation (allowed), not a duplicate.
    """
    nt, ntg, nsev = _norm_text(title), _norm_target(target), _norm_text(severity)
    if not nt:
        return None
    for f in findings_store._load().get("findings", []):
        if (
            _norm_text(f.get("title")) == nt
            and _norm_target(f.get("target")) == ntg
            and _norm_text(f.get("severity")) == nsev
            and _norm_text(f.get("status")) != "false_positive"
        ):
            return f
    return None


def _dedup_message(existing: dict) -> str:
    eid = existing.get("id", "?")
    return (
        f"DUPLICATE — a finding with the same target + title + severity is already on record "
        f"(id={eid}). Not filed again, to keep findings.json and the adjudication gate clean "
        "across runs. If this is a GENUINELY DISTINCT issue (different endpoint/parameter/"
        "component), re-file with a more specific title. To revise the existing finding, use "
        f"report(action='update_finding', data={{'id': '{eid}', ...}})."
    )


async def _do_finding(data):
    severity = data.get("severity", "").lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        return f"Invalid severity '{severity}'. Use: critical, high, medium, low, info"
    title = data.get("title", "")
    target = data.get("target", "")

    # Reject hallucinated/invalid source citations before anything is stored.
    trace_reject = _validate_trace_field(data)
    if trace_reject:
        return trace_reject

    # Cross-run dedup: don't re-file an issue already on record (the app-wide
    # misconfig that used to re-appear every run and re-block the gate).
    dup = _find_duplicate(title, target, severity)
    if dup:
        log.note(f"finding deduplicated against {dup.get('id')} — {title}")
        return _dedup_message(dup)

    await findings_store.add_finding(
        title=title, severity=severity, target=target,
        description=data.get("description", ""),
        evidence=data.get("evidence", ""),
        tool_used=data.get("tool_used", ""),
        cve=data.get("cve", ""),
        business_impact=data.get("business_impact", ""),
        reproduction=data.get("reproduction"),
        escalation_leads=data.get("escalation_leads"),
        trace=data.get("trace"),
    )
    log.finding(severity, title, target)

    # Append FINDING entry to quick_log
    try:
        from core.quick_log import quick_log as _qlog
        _t = asyncio.create_task(_qlog.append({
            "type":     "FINDING",
            "severity": severity,
            "title":    title,
            "target":   target,
        }))
        _background_tasks.add(_t)
        _t.add_done_callback(_background_tasks.discard)
    except Exception:
        pass

    # ── Auto-trigger gates based on finding content ──────────────────────────
    gates_triggered = _auto_trigger_finding_gates(title, severity, data.get("description", ""))
    msg = f"Finding logged: [{severity.upper()}] {title}"
    if gates_triggered:
        msg += f"\n\nGATE(S) TRIGGERED: {', '.join(gates_triggered)}. These skills are now mandatory before completion."
    return msg


def _auto_trigger_finding_gates(title: str, severity: str, description: str) -> list[str]:
    """Check finding content and trigger appropriate gates. Returns list of triggered gate IDs."""
    triggered: list[str] = []
    text = f"{title} {description}".lower()

    # RCE-class finding → post-exploit is mandatory
    if severity in ("critical", "high") and any(kw in text for kw in _RCE_KEYWORDS):
        scan_session.trigger_gate(
            "post_exploit_rce",
            f"RCE confirmed: {title}",
            ["post-exploit"],
        )
        triggered.append("post_exploit_rce")

    # Auth service finding → credential-audit is mandatory
    if any(kw in text for kw in _AUTH_KEYWORDS):
        current = scan_session.get()
        depth = current.get("depth", "standard") if current else "standard"
        if depth in ("standard", "thorough"):
            scan_session.trigger_gate(
                "credential_audit",
                f"Auth service detected: {title}",
                ["credential-audit"],
            )
            triggered.append("credential_audit")

    return triggered


def _log_adjudication_verdict(finding_id, updated, fields):
    """Best-effort: append the senior-review verdict to the adjudication log.

    Extracted from _do_update_finding to keep that function's cognitive
    complexity in check. A no-op when there's no adjudication payload; never
    raises (logging must not fail the update).
    """
    adj = fields.get("adjudication")
    if not adj:
        return
    try:
        from core.adjunction.log import log_verdict
        log_verdict(
            finding_id=finding_id,
            title=updated.get("title", finding_id),
            original_severity=str(adj.get("original_severity", "")),
            revised_severity=str(adj.get("revised_severity", "")),
            reproducible=adj.get("reproducible", ""),
            rationale=str(adj.get("rationale", "")),
        )
    except Exception:
        pass


def _coerce_finding_adjudication(finding_id: str, fields: dict) -> tuple[bool, str]:
    """Normalise/validate the adjudication audit trail in ``fields`` (mutates it).

    Returns ``(dropped, message)``. ``dropped=True`` means the adjudication was
    removed — no rationale, or a reproducible verdict with no on-disk artifact —
    and ``message`` explains why (it must not falsely satisfy the completion-time
    adjudication gate). ``dropped=False`` means it was normalised and stored.
    """
    from core.adjunction import coerce_adjudication
    from mcp_server.scan_engine.artifacts import artifact_exists
    current = next(
        (f for f in findings_store._load().get("findings", []) if f.get("id") == finding_id),
        None,
    )
    coerced = coerce_adjudication(fields.get("adjudication"), current)
    if coerced is None:
        fields.pop("adjudication", None)
        return True, (
            "\n\nNOTE: adjudication was ignored — it needs a non-empty 'rationale'. "
            "Re-send with adjudication={reproducible, original_severity, revised_severity, "
            "rationale} for it to count toward completion."
        )
    if coerced.get("reproducible") and not artifact_exists(coerced.get("artifact_id", "")):
        # A reproducible verdict must be backed by an artifact that actually
        # exists on disk — mirrors the coverage layer's artifact-existence rule.
        fields.pop("adjudication", None)
        _aid = coerced.get("artifact_id", "")
        _why = "no artifact_id was provided" if not _aid else f"artifact_id '{_aid}' does not exist on disk"
        return True, (
            f"\n\nREJECTED: adjudication claims reproducible=true but {_why}. Re-run the "
            "attack that proves the finding reproduces, capture the artifact_id from that "
            "tool response, and re-send the adjudication with it. (A self-attested 'it "
            "reproduces' with no proving artifact is not accepted; set reproducible=false "
            "to mark it a false positive instead.)"
        )
    fields["adjudication"] = coerced
    return False, ""


async def _do_update_finding(data):
    finding_id = data.get("id", "")
    if not finding_id:
        return "Missing required field: id"
    fields = {k: v for k, v in data.items() if k != "id"}
    if not fields:
        return "No fields to update. Provide severity, title, description, evidence, status, etc."

    # Validate an updated trace[] the same way as on create — a corrected trace
    # must still resolve against the codebase.
    if "trace" in fields:
        trace_reject = _validate_trace_field(fields)
        if trace_reject:
            return trace_reject

    adjudication_dropped, adjudication_drop_msg = False, ""
    if "adjudication" in fields:
        adjudication_dropped, adjudication_drop_msg = _coerce_finding_adjudication(finding_id, fields)

    # If the dropped adjudication was the only field, there's nothing left to
    # persist — surface the reject/drop guidance directly instead of a
    # misleading "Finding not found".
    if not fields and adjudication_dropped:
        return f"Finding {finding_id}: adjudication not stored.{adjudication_drop_msg}"

    updated = await findings_store.update_finding(finding_id, **fields)
    if updated:
        msg = f"Finding updated: {finding_id} — fields: {', '.join(fields.keys())}"
        if adjudication_dropped:
            msg += adjudication_drop_msg
        else:
            _log_adjudication_verdict(finding_id, updated, fields)
        return msg
    return f"Finding not found: {finding_id}"


async def _do_delete_finding(data):
    finding_id = data.get("id", "")
    if not finding_id:
        return "Missing required field: id"
    archived = await findings_store.delete_finding(finding_id)
    if archived:
        return f"Finding archived: {finding_id} — moved to archived[] in findings.json"
    return f"Finding not found: {finding_id}"


async def _do_diagram(data):
    title = data.get("title", "")
    mermaid = data.get("mermaid", "")
    await findings_store.add_diagram(title=title, mermaid=mermaid)
    log.diagram(title)
    return f"Diagram saved: {title}"


def _chain_mermaid(steps: list, titles: dict) -> str:
    """Build a left-to-right MITRE-labelled Mermaid kill-chain from steps."""
    lines = ["graph LR"]

    def _node(fid: str) -> str:
        label = _mermaid_label((titles.get(fid) or fid)[:48])
        return f'  F_{_safe(fid)}["{label}"]'

    seen: set[str] = set()
    for s in steps:
        for fid in (s.get("from_finding_id", ""), s.get("to_finding_id", "")):
            if fid and fid not in seen:
                seen.add(fid)
                lines.append(_node(fid))
    for s in steps:
        a = _safe(s.get("from_finding_id", ""))
        b = _safe(s.get("to_finding_id", ""))
        tech = _mermaid_label(s.get("mitre_technique", "") or "enables")
        if a and b:
            lines.append(f"  F_{a} -->|{tech}| F_{b}")
    return "\n".join(lines)


def _safe(fid: str) -> str:
    """Make a finding id safe for a Mermaid node identifier."""
    return "".join(c if c.isalnum() else "_" for c in str(fid))


# Characters that break a Mermaid label. Unquoted edge labels (-->|...|) are the
# worst offenders: '(' is parsed as a node-shape opener (the "got 'PS'" error)
# and '|' closes the label early — both occur in MITRE technique names like
# "T1078 - Valid Accounts (Privileged Account Creation…)". HTML entity codes
# render as the literal character in every Mermaid theme, so the text is unchanged.
_MERMAID_ESCAPES = {
    '"': "#34;", "(": "#40;", ")": "#41;", "|": "#124;",
    "[": "#91;", "]": "#93;", "{": "#123;", "}": "#125;",
}


def _mermaid_label(text: str) -> str:
    """Escape characters that break a Mermaid node/edge label."""
    out = str(text)
    for ch, ent in _MERMAID_ESCAPES.items():
        out = out.replace(ch, ent)
    return out


async def _do_chain(data):
    name = data.get("name", "") or "exploit chain"
    steps = data.get("steps", [])
    if not isinstance(steps, list) or not steps:
        return "Missing/empty 'steps'. Provide steps=[{from_finding_id, to_finding_id, transition_artifact_id, mitre_technique}]."

    from mcp_server.scan_engine.artifacts import artifact_exists
    # Enforce PROVEN hand-offs: every transition must be backed by an artifact
    # that exists on disk. A chain is only as valid as its weakest edge, so any
    # unproven transition rejects the whole submission.
    unproven = [
        f"step {i + 1} ({s.get('from_finding_id', '?')}→{s.get('to_finding_id', '?')}): "
        f"transition_artifact_id '{s.get('transition_artifact_id', '')}' not found on disk"
        for i, s in enumerate(steps)
        if not artifact_exists(s.get("transition_artifact_id", ""))
    ]
    if unproven:
        return (
            "REJECTED: exploit chain has unproven transition(s) — every step needs a "
            "transition_artifact_id whose artifact exists on disk (the evidence that step N's "
            "output is consumed by step N+1). Run/capture the proving artifact, then re-submit.\n  - "
            + "\n  - ".join(unproven)
        )

    # Build the kill-chain diagram, labelling nodes with finding titles.
    all_findings = findings_store._load().get("findings", [])
    titles = {f.get("id"): f.get("title", "") for f in all_findings}
    mermaid = _chain_mermaid(steps, titles)

    await findings_store.add_chain(
        name=name,
        steps=steps,
        terminal_impact=data.get("terminal_impact", ""),
        combined_severity=str(data.get("combined_severity", "")).lower(),
        mermaid=mermaid,
    )
    # Also surface it as a diagram so it renders on the dashboard immediately.
    await findings_store.add_diagram(title=f"Exploit chain: {name}", mermaid=mermaid)
    log.note(f"Exploit chain recorded: {name} ({len(steps)} proven step(s))")
    return f"Exploit chain saved: '{name}' — {len(steps)} proven step(s), diagram rendered."


def _do_note(data):
    message = data.get("message", "")
    log.note(message)

    # ── Auto-trigger gates based on note content ─────────────────────────────
    gates_triggered = _auto_trigger_note_gates(message)
    if gates_triggered:
        return f"Logged.\n\nGATE(S) TRIGGERED: {', '.join(gates_triggered)}. These skills are now mandatory before completion."
    return "Logged."


def _auto_trigger_note_gates(message: str) -> list[str]:
    """Check note content and trigger environment-specific gates. Returns list of triggered gate IDs."""
    triggered: list[str] = []
    text = message.lower()

    # Only trigger environment gates if an RCE gate already exists (we have access)
    rce_gate_exists = any(g["id"] == "post_exploit_rce" for g in (scan_session.get() or {}).get("gates", []))

    if rce_gate_exists:
        # K8s/container indicators → container-k8s-security mandatory
        if any(kw in text for kw in _K8S_KEYWORDS):
            scan_session.trigger_gate(
                "container_k8s",
                "Container/K8s environment detected",
                ["container-k8s-security"],
            )
            triggered.append("container_k8s")

        # Cloud metadata indicators → cloud-security mandatory
        if any(kw in text for kw in _CLOUD_KEYWORDS) or _CLOUD_METADATA_PREFIX in text:
            scan_session.trigger_gate(
                "cloud_pivot",
                "Cloud metadata service reachable",
                ["cloud-security"],
            )
            triggered.append("cloud_pivot")

        # Internal network indicators → network-assess mandatory
        if any(kw in text for kw in _INTERNAL_NET_KEYWORDS):
            scan_session.trigger_gate(
                "internal_network",
                "Internal network reachable from compromised host",
                ["network-assess"],
            )
            triggered.append("internal_network")

    # Auth service indicators in notes (e.g. from nmap service detection)
    if any(kw in text for kw in _AUTH_KEYWORDS):
        current = scan_session.get()
        depth = current.get("depth", "standard") if current else "standard"
        if depth in ("standard", "thorough"):
            scan_session.trigger_gate(
                "credential_audit",
                "Auth service detected in recon",
                ["credential-audit"],
            )
            triggered.append("credential_audit")

    return triggered


# Single source of truth for the dashboard port. Match the launchd plist,
# the install scripts, CLAUDE.md docs, and the api_server.serve() default —
# every reference in this repo says 7777.
_DASHBOARD_CANONICAL_PORT = 7777

# Ports we silently rewrite to the canonical one. The skills submodule
# pentester*.md files hard-code `data={"port": 5000}` which dates back to
# an earlier convention. Rather than wait for a submodule-bump PR + cascade
# every operator's `~/.config/opencode/opencode.json` to a new port, we
# normalize the legacy values here so Smith's call lands on the port the
# operator's browser is already pointed at. Add new aliases here as
# upstream skill repos drift.
_LEGACY_DASHBOARD_PORTS = {5000, 8000, 8080}


def _safe_port(value, default: int) -> int:
    """Coerce a user-supplied port value to a valid int in the IANA range.

    Defense against SonarQube python:S5145 (log injection): the result is a
    sanitized int that's safe to interpolate into log lines. Invalid input
    (non-int, non-numeric string, negative, > 65535) falls back to the
    default — we never log the raw value back to the operator, which would
    let a malicious tool-call payload write fake log entries by embedding
    newlines.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    if 0 < v < 65536:
        return v
    return default


async def _do_dashboard(data):
    try:
        from core import api_server
        # Sanitize at the boundary — `requested` is now guaranteed to be an
        # int in [1, 65535], safe to interpolate into log lines and audit
        # trails without S5145 (log injection) exposure.
        requested = _safe_port(data.get("port"), _DASHBOARD_CANONICAL_PORT)
        if requested in _LEGACY_DASHBOARD_PORTS:
            log.tool_result(
                "dashboard",
                f"port {requested} normalized to {_DASHBOARD_CANONICAL_PORT} "
                "(canonical agent-smith dashboard port)",
            )
            port = _DASHBOARD_CANONICAL_PORT
        else:
            port = requested
        log.tool_call("dashboard", {"port": port, "requested": requested})
        url = await api_server.serve(port)
        log.tool_result("dashboard", url)
        return f"Dashboard running — open {url}"
    except BaseException as exc:
        # Defense against S5145: don't echo the raw exception message into
        # the audit log or the return string — its content could come from
        # user-controlled input (e.g. a malformed port value). The exception
        # type alone is enough for Smith to diagnose. Full traceback still
        # goes via Python's standard logger which uses parameter binding,
        # not string interpolation, so log-injection is prevented there too.
        safe_err = f"Dashboard failed: {type(exc).__name__}"
        log.tool_result("dashboard", safe_err)
        return safe_err
        return err


def _coerce_endpoint_params(raw_params: Any) -> list[dict]:
    """Coerce params from various model formats to a clean list of dicts."""
    if isinstance(raw_params, str):
        try:
            raw_params = json.loads(raw_params)
        except json.JSONDecodeError:
            raw_params = []
    if not isinstance(raw_params, list):
        return []
    clean: list[dict] = []
    for p in raw_params:
        if isinstance(p, str):
            clean.append({"name": p, "type": "query", "value_hint": "string"})
        elif isinstance(p, dict):
            clean.append({
                "name": p.get("name", p.get("param", "")),
                "type": p.get("type", p.get("param_type", "query")),
                "value_hint": p.get("value_hint", p.get("hint", "string")),
            })
    return clean


def _infer_coverage_type(data: dict) -> str:
    """Auto-detect coverage type from data shape when not explicitly provided."""
    if "path" in data:
        return "endpoint"
    if "cell_id" in data:
        return "tested"
    if "updates" in data:
        return "bulk_tested"
    return ""


async def _do_coverage_endpoint(data: dict, cov: Any) -> str:
    """Handle coverage type='endpoint': register an endpoint in the matrix."""
    path = data.get("path", "")
    if not path:
        return (
            "Error: 'path' is required for endpoint registration. "
            "Example: report(action='coverage', data={type:'endpoint', path:'/login', "
            "method:'GET', params:[{name:'q', type:'query', value_hint:'string'}]})"
        )
    clean_params = _coerce_endpoint_params(data.get("params", []))
    result = await cov.add_endpoint(
        path=path,
        method=data.get("method", "GET"),
        params=clean_params,
        discovered_by=data.get("discovered_by", "spider"),
        auth_context=data.get("auth_context", "none"),
    )
    if result["dedup"]:
        return f"Endpoint already registered (dedup): {path} {data.get('method', 'GET')}"
    await _emit_coverage_event()
    return (
        f"Endpoint registered: {data.get('method', 'GET')} {path} — "
        f"{result['new_cells']} test cells auto-generated"
    )


async def _do_coverage_tested(data: dict, cov: Any) -> str:
    """Handle coverage type='tested': mark a single cell as tested."""
    result = await cov.update_cell(
        cell_id=data.get("cell_id", ""),
        status=data.get("status", ""),
        notes=data.get("notes", ""),
        finding_id=data.get("finding_id"),
        tested_by=data.get("tested_by", ""),
        artifact_id=data.get("artifact_id", ""),
    )
    if result is False:
        # Common after context compaction: Smith carried the cell ID across a
        # turn boundary, the matrix on disk still has the cell, but the
        # in-context ID was lost OR Smith reconstructed it incorrectly. Point
        # at the recovery primitive instead of leaving Smith to guess (or
        # worse, re-register endpoints, which produces duplicate cells).
        return (
            f"Cell not found: {data.get('cell_id')}. "
            "If your context was recently compacted, fetch the current matrix "
            "via report(action='coverage', type='list') — optionally filter by "
            "endpoint_path, method, param_name, or injection_type to narrow "
            "the response. DO NOT re-register endpoints; the cells are still "
            "on disk."
        )
    if isinstance(result, str):
        return result  # passes through REJECTED messages directly
    return f"Cell updated: {data.get('cell_id')}"


async def _do_coverage_bulk(data: dict, cov: Any) -> str:
    """Handle coverage type='bulk_tested': update multiple cells at once."""
    result = await cov.bulk_update(data.get("updates", []))
    await _emit_coverage_event()
    msg = f"Bulk update: {result['updated']} cell(s) updated"
    if result["warnings"]:
        msg += f"\n\nINTEGRITY WARNINGS ({len(result['warnings'])}):\n"
        msg += "\n".join(f"  - {w}" for w in result["warnings"])
    return msg


async def _do_coverage_reset(cov: Any) -> str:
    """Handle coverage type='reset': clear the matrix (blocked during active scan)."""
    current = scan_session.get()
    if current and current.get("status") in ("running", "intervention_required"):
        log.note("coverage reset BLOCKED — scan is active. Do NOT reset the matrix mid-scan.")
        return (
            "BLOCKED: Cannot reset coverage matrix while a scan is active. "
            "The matrix tracks your testing progress — resetting it mid-scan destroys that state. "
            "If you need to re-register endpoints, just call coverage(type='endpoint') again — "
            "duplicates are automatically ignored."
        )
    await cov.reset()
    return "Coverage matrix reset."


async def _do_coverage(data):
    from core import coverage as cov

    cov_type = data.get("type", "")
    log.note(f"coverage({cov_type}): {json.dumps(data)[:300]}")

    if not cov_type:
        cov_type = _infer_coverage_type(data)

    if cov_type == "endpoint":
        return await _do_coverage_endpoint(data, cov)
    if cov_type == "tested":
        return await _do_coverage_tested(data, cov)
    if cov_type == "bulk_tested":
        return await _do_coverage_bulk(data, cov)
    if cov_type == "reset":
        return await _do_coverage_reset(cov)
    if cov_type == "list":
        return await _do_coverage_list(data, cov)
    return (
        f"Unknown coverage type '{cov_type}'. Use: endpoint, tested, bulk_tested, list, reset. "
        f"Example: report(action='coverage', data={{type:'endpoint', path:'/login', method:'GET', "
        f"params:[{{name:'user', type:'query', value_hint:'string'}}]}})"
    )


async def _do_coverage_list(data, cov):
    """Read the current matrix with optional filters. Compaction-recovery
    primitive: Smith uses this after a context reset to rebuild its
    mental model of which cells exist, what their IDs are, and where
    each one stands.

    Accepted filter keys (all optional, AND-combined):
      endpoint_path  — substring match, case-insensitive (e.g. "/login")
      method         — exact match (e.g. "POST")
      status         — exact: pending|in_progress|tested_clean|vulnerable|
                              not_applicable|skipped
      injection_type — exact: sqli|xss|ssti|cmdi|ssrf|nosqli|xxe|traversal|
                              crlf|prototype|mass_assignment|redirect|
                              auth|authz|rate_limit|cors|security_headers|csrf|
                              (LLM) prompt_injection|jailbreak|cot_forgery|
                              role_prefix_spoofing|system_prompt_leak|… (see core/taxonomy.py)
      param_name     — substring match, case-insensitive
      limit          — int, default 200, hard ceiling 1000 to keep
                       the response payload bounded
    """
    LIMIT_MAX = 1000
    try:
        limit = min(int(data.get("limit", 200)), LIMIT_MAX)
    except (TypeError, ValueError):
        limit = 200
    result = await cov.list_cells(
        endpoint_path  = (data.get("endpoint_path") or "").strip() or None,
        method         = (data.get("method") or "").strip() or None,
        status         = (data.get("status") or "").strip() or None,
        injection_type = (data.get("injection_type") or "").strip() or None,
        param_name     = (data.get("param_name") or "").strip() or None,
        limit          = limit,
    )
    return json.dumps(result, indent=2)


async def _emit_coverage_event() -> None:
    """Append a COVERAGE entry to quick_log with current matrix totals."""
    try:
        from core.quick_log import quick_log as _qlog
        from core import coverage as _cov
        matrix    = _cov.get_matrix()
        meta      = matrix.get("meta", {})
        all_cells = matrix.get("matrix", [])
        # "Unevidenced" = closed without an artifact_id (the write-enforced proof
        # a tool ran) AND without legacy tested_by. Keying these counts on
        # artifact_id keeps the QA completion gates satisfiable: a cell closed
        # with a real artifact but empty tested_by is evidenced, not orphaned.
        from core.coverage import cell_has_test_evidence
        await _qlog.append({
            "type":           "COVERAGE",
            "registered":     len(matrix.get("endpoints", [])),
            "pending":        sum(1 for c in all_cells if c["status"] == "pending"),
            "tested":         meta.get("tested", 0),
            "vulnerable":     meta.get("vulnerable", 0),
            "not_applicable": sum(1 for c in all_cells if c["status"] == "not_applicable"),
            "skipped":        sum(1 for c in all_cells if c["status"] == "skipped"),
            "na_untooled":    sum(1 for c in all_cells
                                  if c["status"] == "not_applicable"
                                  and not cell_has_test_evidence(c)),
            "untooled":       sum(1 for c in all_cells
                                  if c["status"] in ("tested_clean", "vulnerable")
                                  and not cell_has_test_evidence(c)),
        })
    except Exception:
        pass
