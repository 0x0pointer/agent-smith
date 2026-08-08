"""
Diagram, exploit-chain, note, and dashboard actions.
"""
from ._common import (
    findings_store,
    log,
    scan_session,
    _safe,
    _mermaid_label,
    _safe_port,
)
from .gates import _auto_trigger_note_gates


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


def _suggest_chains() -> str:
    """Surface graph-derived candidate kill-chains (AR-B3). Fenced target text."""
    from core.graph import build_graph, candidate_chains
    from core.prompt_fence import fence as _fence
    try:
        props = candidate_chains(build_graph())
    except Exception as exc:  # fail-soft — never break on a graph error
        return f"Chain suggestion unavailable: {exc}"
    if not props:
        return ("No multi-step chains proposable yet — need ≥2 related findings, an "
                "escalation lead, or a credential leak. Keep exploiting; re-run "
                "report(action='chain', data={type:'suggest'}) as findings accrue.")
    lines = [f"🔗 {len(props)} candidate chain(s) to PROVE (then file with artifact-backed steps):"]
    for i, p in enumerate(props[:8], 1):
        arrow = " → ".join(_fence(s) for s in p["steps"])
        lines.append(f"  {i}. [{p['combined_severity']}] {arrow}\n     terminal: {_fence(p['terminal'])} — {p['rationale']}")
    return "\n".join(lines)


async def _do_chain(data):
    # Phase 2 / AR-B3: type='suggest' returns GRAPH-DERIVED candidate chains for
    # the model to prove — the kill chain was previously 100% model-declared with
    # nothing proposing which finding feeds which. Proposals only; recording a
    # chain still requires the artifact-backed steps below.
    if data.get("type") == "suggest":
        return _suggest_chains()

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


def _providers_of(g, prims: set) -> list:
    """Findings that PROVIDE any primitive in `prims`, as (finding_node, primitive)."""
    from core.graph import model as m
    from core.graph.chains import _sev
    out = []
    for p in prims:
        for e in g.in_edges(f"prim:{p}", m.PROVIDES):
            fn = g.nodes.get(e.src)
            if fn is not None:
                out.append((fn, p))
    out.sort(key=lambda pr: _sev(pr[0]), reverse=True)
    return out


def _blocked_finding_for(g, note_text: str, exclude_id: str, host: str | None):
    """Conservatively pick the FINDING the dead-end note refers to: a non-provider
    finding (same host as the provider, if known) whose title shares a distinctive
    word with the note. Returns bare finding id or None (skip back-fill if unsure —
    a wrong attachment is worse than none)."""
    from core.graph import model as m
    from core.graph.chains import _host
    best, best_hits = None, 0
    words = {w for w in note_text.replace("/", " ").split() if len(w) >= 5}
    for fn in g.of_kind(m.FINDING):
        if fn.id == exclude_id:
            continue
        if host and _host(g, fn.id) and _host(g, fn.id) != host:
            continue
        title = (fn.label or "").lower()
        hits = sum(1 for w in words if w in title)
        if hits > best_hits:
            best, best_hits = fn, hits
    if best and best_hits >= 1:
        return best.id.replace("finding:", "", 1)
    return None


async def _maybe_push_composition_bridge(message: str) -> str | None:
    """SURFACE layer: when a NOTE declares a dead-end blocked on a missing primitive,
    and another confirmed finding already PROVIDES it, (1) back-fill the `requires`
    primitive onto the blocked finding so OBLIGATE + the metric have a persisted signal
    (the failing agent won't self-declare it), and (2) push ONE COMPOSE_REQUIRED steer
    naming the provider. Gated on a real graph-matched provider — a stray 'blocked'
    phrase with no provider yields nothing."""
    from core.gate_keywords import BLOCKED_MARKERS
    text = message.lower()
    if not any(mk in text for mk in BLOCKED_MARKERS):
        return None
    from core.graph import primitives as prim
    blocked_prims = prim.classify_requires(message, "")
    if not blocked_prims:
        return None
    try:
        from core.graph import build_graph
        from core.graph.chains import _host
        g = build_graph()
    except Exception:
        return None
    providers = _providers_of(g, blocked_prims)
    if not providers:
        return None
    provider, primitive = providers[0]

    # Back-fill `requires` onto the blocked finding so the signal persists.
    blocked_fid = _blocked_finding_for(g, text, provider.id, _host(g, provider.id))
    if blocked_fid:
        try:
            existing = next((f.get("requires", []) for f in findings_store._load().get("findings", [])
                             if f.get("id") == blocked_fid), [])
            merged = sorted(set(list(existing) + [primitive]))
            await findings_store.update_finding(blocked_fid, requires=merged)
        except Exception:
            pass

    try:
        from core.steering import steering_queue, COMPOSE_REQUIRED
        pushed = steering_queue.add_directive(
            code=COMPOSE_REQUIRED,
            message=(
                f"COMPOSITIONAL BRIDGE — you noted a dead-end blocked on '{primitive}'. "
                f"Finding '{provider.label}' already PROVIDES {primitive} — use it to unblock the "
                f"step (e.g. a Postgres SQLi's pg_read_server_file gives file_read to leak a "
                f"Werkzeug PIN), then file report(action='chain', ...) with the transition artifact. "
                f"If it genuinely doesn't work, record why via update_finding so the block is documented."
            ),
            priority="high", trigger="BLOCKED_PRIMITIVE_BRIDGE",
        )  # COMPOSE_REQUIRED is a distinct dedup slot — won't be suppressed by RESUME_TESTING
        if pushed:
            return f"'{provider.label}' provides {primitive}"
    except Exception:
        pass
    return None


async def _do_note(data):
    message = data.get("message", "")
    log.note(message)

    # ── Auto-trigger gates based on note content ─────────────────────────────
    gates_triggered = _auto_trigger_note_gates(message)
    # ── Compositional bridge: dead-end note + a finding that provides the primitive ──
    bridge = await _maybe_push_composition_bridge(message)

    parts = ["Logged."]
    if gates_triggered:
        parts.append(f"GATE(S) TRIGGERED: {', '.join(gates_triggered)}. These skills are now mandatory before completion.")
    if bridge:
        parts.append(f"COMPOSITIONAL BRIDGE available — {bridge}. A steer was queued: use that finding's primitive to unblock this dead-end, then file report(action='chain').")
    return "\n\n".join(parts)


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
        # Carry the per-session bearer token in the URL fragment (never sent to
        # the server, stays out of access logs). The dashboard JS captures it into
        # sessionStorage and sends it as Authorization: Bearer on every /api call.
        try:
            from core import dashboard_auth
            tok = dashboard_auth.read_token()
            if tok and url.startswith("http"):
                url = f"{url}/#k={tok}"
        except Exception:
            pass
        log.tool_result("dashboard", url)
        return (f"Dashboard running — open {url}\n"
                "⚠ AI-generated content may be incorrect. It should always be validated by a person.")
    except Exception as exc:
        # Defense against S5145: don't echo the raw exception message into
        # the audit log or the return string — its content could come from
        # user-controlled input (e.g. a malformed port value). The exception
        # type alone is enough for Smith to diagnose. Full traceback still
        # goes via Python's standard logger which uses parameter binding,
        # not string interpolation, so log-injection is prevented there too.
        safe_err = f"Dashboard failed: {type(exc).__name__}"
        log.tool_result("dashboard", safe_err)
        return safe_err
