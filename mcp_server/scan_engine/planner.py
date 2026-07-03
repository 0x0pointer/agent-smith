"""
Coverage-driven planner — computes next actions and detects behavioral drift.

Called by the envelope wrapper on every tool response. Returns required actions
(obligations the model must fulfill) and recommended actions (suggestions).
Also detects drift: duplicate tests, phase-inappropriate tools, skipped coverage.
"""
from __future__ import annotations

from core import session as scan_session
from core.coverage import get_matrix, select_next_batch
from core.prompt_fence import fence as _fence


def _add_recon_actions(required: list[str], recommended: list[str], tools_run: set, target: str) -> None:
    """Compute required/recommended actions for the recon phase."""
    if "httpx" not in tools_run:
        required.append(f"Run httpx: scan(tool='httpx', target='{target}')")
    if "naabu" not in tools_run and "nmap" not in tools_run:
        recommended.append(f"Port scan: scan(tool='naabu', target='{target}')")
    if "subfinder" not in tools_run:
        recommended.append(f"Subdomain enum: scan(tool='subfinder', target='{target}')")


def _add_discovery_actions(required: list[str], recommended: list[str], tools_run: set, target: str) -> None:
    """Compute required/recommended actions for the discovery phase."""
    if "spider" not in tools_run:
        required.append(f"Crawl endpoints: scan(tool='spider', target='{target}')")
    else:
        required.append(
            "Register endpoints in coverage matrix: "
            "report(action='coverage', data={type:'endpoint', path:'...', method:'GET', "
            "params:[{name, type, value_hint}], discovered_by:'spider'})"
        )
    if "nuclei" not in tools_run:
        recommended.append(f"Vulnerability scan: scan(tool='nuclei', target='{target}')")
    if "ffuf" not in tools_run:
        recommended.append(f"Directory fuzzing: scan(tool='ffuf', target='{target}')")


def _inject_pending_gates(required: list[str]) -> None:
    """Synchronously inject open skill-chain gates as required actions.

    This is the proactive mechanism — gates fire in the same tool response that
    triggered them, while the agent still has full context of the discovery.
    The QA daemon's 2-minute delayed alert is a fallback only.
    """
    try:
        from core import session as scan_session
        pending_gates = scan_session.pending_gates()
        if not pending_gates:
            return
        satisfied_skills = {
            e["skill"] for e in (scan_session.get() or {}).get("skill_history", [])
        }
        for gate in pending_gates:
            missing = [
                s for s in gate.get("required_skills", [])
                if s not in satisfied_skills
            ]
            if not missing:
                continue
            trigger = gate.get("trigger", "")
            for skill in missing:
                required.insert(0, (
                    f"CHAIN REQUIRED (before completion): /{skill} — gate '{gate['id']}' triggered by {_fence(trigger)}. "
                    f"Finish your current recon/mapping step first if you're mid-task, then chain it: "
                    f"session(action='set_skill', options={{skill: '{skill}', reason: 'gate {gate['id']}'}}) then Skill('{skill}'). "
                    "Don't leave it unaddressed — this gate blocks completion."
                ))
            # Inject at most one gate per response to avoid context flooding.
            break
    except Exception:
        pass


def _has_pending_directives() -> bool:
    """Return True if Smith already has an unacknowledged steering directive."""
    import json
    import pathlib
    _steering = pathlib.Path(__file__).resolve().parent.parent.parent / "steering_queue.json"
    try:
        data = json.loads(_steering.read_text()) if _steering.exists() else {}
        return any(
            d.get("status") in ("pending", "injected")
            for d in data.get("directives", [])
        )
    except Exception:
        return False


def compute_next(tool: str, state: dict) -> dict:
    """Compute next actions based on current state.

    Returns {"required": [...], "recommended": [...], "warnings": [...]}.
    When a steering directive is pending, required and recommended are suppressed —
    the directive is Smith's only job until acknowledged.
    """
    required: list[str] = []
    recommended: list[str] = []
    warnings: list[str] = []

    phase = state.get("phase", "idle")
    tools_run = set(state.get("tools_run", []))
    target = state.get("target", "")

    if phase == "idle":
        required.append(f"Start scan: session(action='start', options={{target: '{target}', depth: 'thorough'}})")
        return {"required": required, "recommended": recommended, "warnings": warnings}

    # When a steering directive is active, suppress all planner output.
    # Smith's only job is to execute the directive — additional required/recommended
    # actions create competing obligations and increase the chance of shortcuts.
    if _has_pending_directives():
        return {"required": [], "recommended": [], "warnings": warnings}

    # Proactive gate injection — synchronous, fires on same response as trigger
    _inject_pending_gates(required)

    # --- Drift detection ---
    drift = _detect_drift(tool, phase, tools_run)
    warnings.extend(drift)

    # --- Phase-specific next actions ---
    if phase == "recon":
        _add_recon_actions(required, recommended, tools_run, target)
    elif phase == "discovery":
        _add_discovery_actions(required, recommended, tools_run, target)
    elif phase == "testing":
        _add_testing_actions(required, recommended, target)
    elif phase == "validation":
        recommended.append("Save PoCs: http(action='save_poc', ...) for each finding")
        recommended.append("Create architecture diagram: report(action='diagram', data={title, mermaid})")
        recommended.append("Complete scan: session(action='complete')")

    # Graph-derived steering (Phase 2): push the highest-value finding to deepen +
    # the highest-value untested endpoint into the per-turn recommendations, so the
    # world-model actively STEERS the loop instead of only informing recovery.
    if phase in ("testing", "validation"):
        _add_graph_steer(recommended)

    return {"required": required, "recommended": recommended, "warnings": warnings}


def _add_graph_steer(recommended: list[str]) -> None:
    """Append graph-ranked next actions (WF-A5 / value ranking). Fail-soft +
    fenced (finding/endpoint text is target-derived)."""
    try:
        from core.graph import build_graph, next_targets, rank_findings
        g = build_graph()
        ranked = rank_findings(g)
        if ranked:
            top = ranked[0]
            recommended.append(
                f"Deepen the highest-value finding: {_fence(top['label'])} "
                f"[{top['severity']}] — {top['why']}. Chain it: report(action='chain', data={{type:'suggest'}})")
        tgts = next_targets(g, limit=1)
        if tgts:
            recommended.append(
                f"Highest-value untested endpoint: {_fence(tgts[0]['path'])} "
                f"({tgts[0]['pending_cells']} pending cell(s)) — sweep it: "
                "report(action='coverage', data={type:'sweep'})")
    except Exception:
        pass


def _add_testing_actions(required: list[str], recommended: list[str], target: str) -> None:
    """Continuously drive the model through the coverage matrix.

    On every tool response, hand the next FOCUSED batch (endpoint-grouped, profile-
    sized) with the concrete request for each cell, plus progress — so the model is
    always being pulled toward the matrix and never drifts into "I found some bugs,
    I'm done". The matrix is the deliverable; finding bugs happens *while* working
    it. Anti-grind: the commands are REAL probes (sqlmap for sqli, targeted
    payloads), the framing forbids canned filler, and the honesty guards + the
    completion coverage-gate reject shallow tested_clean closures — so this drives
    honest testing rather than the naive single-payload grind that the old forced
    10-cell batch produced.
    """
    cov = get_matrix()
    matrix = cov.get("matrix", [])
    in_progress = [c for c in matrix if c["status"] == "in_progress"]
    if in_progress:
        cell = in_progress[0]
        ep = {e["id"]: e for e in cov.get("endpoints", [])}.get(cell["endpoint_id"], {})
        required.append(
            f"Continue testing (then close the cell): {cell['injection_type']} on "
            f"{ep.get('method', '?')} {ep.get('path', '?')} param={cell['param']} (cell {cell['id']})"
        )
        return

    if not any(c["status"] == "pending" for c in matrix):
        recommended.append("All cells addressed — proceed to validation/reporting")
        return

    from mcp_server.scan_engine.budget import get_profile
    profile = get_profile()
    count = profile.get("next_batch_size", 5)
    # enforce_coverage gates the FRAMING of this drive. ON (full): the matrix is the
    # deliverable, so the batch is a REQUIRED action with "the scan finishes when the
    # matrix is worked". OFF (local medium/small): coverage is advisory — surface the
    # same cells as OPTIONAL guidance the model can pursue alongside its exploit leads.
    # The hard "you're not done until the matrix is worked" framing is exactly what
    # made a small local model spin on an unservable 700-cell matrix and stall.
    enforce_cov = bool(profile.get("enforce_coverage", True))
    sel = select_next_batch(cov, count=count)
    batch = sel.get("batch", [])
    if not batch:
        return

    prog = sel.get("progress", {})
    foc = sel.get("endpoint_focus") or {}
    lines = []
    for c in batch:
        cmd = _concrete_test_command(
            c.get("injection_type", ""), target,
            c.get("endpoint_path") or "?", c.get("method") or "?",
            c.get("param") or "_endpoint", c.get("param_type") or "query",
        )
        lines.append(f"  • {cmd} (cell {c.get('cell_id')})")

    rem = sel.get("remaining", 0)
    if enforce_cov:
        required.append(
            f"WORK THE MATRIX (it's the deliverable) — next {len(batch)} cell(s) on "
            f"{foc.get('method', '?')} {foc.get('path', '?')} [this endpoint {prog.get('endpoint', '?')} · "
            f"overall {prog.get('overall', '?')}]. Test each with a REAL probe (commands below — never "
            f"canned filler; one benign response is NOT proof a cell is clean), then close it with its "
            f"artifact_id via report(action='coverage', data={{type:'bulk_tested', updates:[...]}}). The "
            f"scan finishes when the matrix is worked, not when you've found a few bugs:\n" + "\n".join(lines)
        )
        if rem > len(batch):
            recommended.append(
                f"{rem} cells pending overall — call report(action='coverage', data={{type:'next_batch'}}) "
                "any time for the next focused batch."
            )
        return

    # Local profile — advisory guidance, never a completion gate.
    recommended.append(
        f"Optional coverage — {len(batch)} pending cell(s) on {foc.get('method', '?')} "
        f"{foc.get('path', '?')} [overall {prog.get('overall', '?')}] you can probe alongside your "
        f"exploit leads. Test with a REAL probe, then close with its artifact_id via "
        f"report(action='coverage', data={{type:'bulk_tested', updates:[...]}}). Coverage is advisory "
        f"for this profile — follow the strongest leads and complete on findings; the matrix is "
        f"recorded, not a gate:\n" + "\n".join(lines)
    )


def _resolve_url(target: str, path: str, param: str, param_type: str, payload: str) -> str:
    """Build the test URL, handling path vs query params correctly."""
    import re
    if param_type == "path":
        # Replace {id} or {param_name} in path with payload
        resolved = re.sub(r'\{[^}]+\}', payload, path, count=1)
        return f"{target}{resolved}"
    if param == "_endpoint":
        # Endpoint-level test (no specific param) — just use the URL
        return f"{target}{path}"
    # Query param
    return f"{target}{path}?{param}={payload}"


# CH-1: route the probe payload by the fingerprint already in known_assets, so a
# real probe fires for the detected stack instead of a generic {{7*7}} a non-Jinja
# engine ignores. The single most valuable chaining signal (tech) was inert before.
# Default SSTI arithmetic probe for Jinja-family engines (evaluates to 49).
_JINJA_SSTI_PROBE = "{{7*7}}"
_SSTI_BY_TECH: list[tuple[tuple[str, ...], str]] = [
    (("freemarker",), "${7*7}"),
    (("velocity",), "#set($x=7*7)${x}"),
    (("thymeleaf", "spring"), "${7*7}"),
    (("erb", "rails", "ruby", "puma", "passenger"), "<%= 7*7 %>"),
    (("smarty",), "{7*7}"),
    (("jinja", "flask", "werkzeug", "django", "twig", "symfony",
      "nunjucks", "handlebars", "express", "node"), _JINJA_SSTI_PROBE),
]
_WINDOWS_TECH = ("iis", "asp.net", "microsoft-httpapi", "kestrel", "windows")


def _known_techs() -> str:
    ka = (scan_session.get() or {}).get("known_assets") or {}
    return " ".join(str(t) for t in (ka.get("technologies") or [])).lower()


def _routed_payload(inj: str, default: str, techs: str) -> str:
    """Tech-specific payload for ssti/cmdi/traversal; ``default`` otherwise."""
    if not techs:
        return default
    is_win = any(t in techs for t in _WINDOWS_TECH)
    if inj == "ssti":
        for needles, pl in _SSTI_BY_TECH:
            if any(n in techs for n in needles):
                return pl
        return default
    if inj == "cmdi":
        return "& whoami" if is_win else default
    if inj == "traversal":
        return r"..\..\..\windows\win.ini" if is_win else default
    return default


def _injection_command_with_payload(inj: str, target: str, path: str, method: str, param: str, param_type: str) -> str | None:
    """Return the tool-call string for injection types that require a payload in the URL.

    Returns None when the injection type is not handled here.
    """
    if inj == "sqli":
        if param_type == "path":
            test_url = _resolve_url(target, path, param, param_type, "1*")
            return f"kali(command=\"sqlmap -u '{test_url}' --batch --level=2\")"
        return f"kali(command=\"sqlmap -u '{_resolve_url(target, path, param, param_type, 'test')}' --batch --level=2\")"
    payloads = {
        "xss": "<script>alert(1)</script>",
        "ssti": _JINJA_SSTI_PROBE,
        "cmdi": ";id",
        "ssrf": "http://127.0.0.1:80",
        "traversal": "....//....//etc/passwd",
    }
    _techs = _known_techs()
    for _inj in ("ssti", "cmdi", "traversal"):
        payloads[_inj] = _routed_payload(_inj, payloads[_inj], _techs)
    if inj in payloads:
        test_url = _resolve_url(target, path, param, param_type, payloads[inj])
        return f"http(action='request', url='{test_url}', method='{method}')"
    if inj == "idor":
        test_url = _resolve_url(target, path, param, param_type, "1")
        test_url2 = _resolve_url(target, path, param, param_type, "2")
        return f"http(action='request', url='{test_url}', method='{method}') then compare with url='{test_url2}'"
    return None


def build_probe(inj: str, target: str, path: str, method: str, param: str,
                param_type: str = "query") -> dict | None:
    """Structured probe for the server-side sweep (SM-5). Unlike
    _concrete_test_command (a human-readable string), this returns the params the
    sweep executes directly. ``None`` when the type isn't server-side sweepable.

      {"kind": "http", "url", "method", "payload"}   # inject payload, read response
      {"kind": "kali", "cmd", "payload": ""}          # sqlmap runs its own oracle
    """
    techs = _known_techs()
    if inj == "sqli":
        seed = "1*" if param_type == "path" else "test"
        url = _resolve_url(target, path, param, param_type, seed)
        return {"kind": "kali", "payload": "",
                "cmd": f"sqlmap -u '{url}' --batch --level=2"}
    http_payloads = {
        "xss": "<script>alert(1)</script>",
        "ssti": _routed_payload("ssti", _JINJA_SSTI_PROBE, techs),
        "cmdi": _routed_payload("cmdi", ";id", techs),
        "traversal": _routed_payload("traversal", "....//....//etc/passwd", techs),
    }
    if inj in http_payloads:
        payload = http_payloads[inj]
        return {"kind": "http", "method": method, "payload": payload,
                "url": _resolve_url(target, path, param, param_type, payload)}
    return None  # ssrf/xxe/nosqli/idor/… need OOB / diffing / judgment — not swept


def _injection_command_endpoint_level(inj: str, url: str) -> str | None:
    """Return the tool-call string for endpoint-level injection types (no payload in URL).

    Returns None when the injection type is not handled here.
    """
    if inj == "cors":
        return f"http(action='request', url='{url}', method='GET', headers={{\"Origin\": \"https://evil.com\"}})"
    if inj == "csrf":
        return f"http(action='request', url='{url}', method='POST', headers={{\"Content-Type\": \"application/x-www-form-urlencoded\"}}, body='test=1')"
    if inj == "method_tampering":
        return f"http(action='request', url='{url}', method='PUT')"
    if inj == "cache":
        return f"http(action='request', url='{url}', method='GET', headers={{\"X-Forwarded-Host\": \"evil.com\"}})"
    if inj in ("security_headers", "rate_limit", "jwt", "race"):
        return f"http(action='request', url='{url}', method='GET')"
    return None


def _concrete_test_command(inj: str, target: str, path: str, method: str, param: str, param_type: str = "query") -> str:
    """Return an exact tool call string for the given injection type."""
    url = f"{target}{path}"
    result = _injection_command_with_payload(inj, target, path, method, param, param_type)
    if result is not None:
        return result
    result = _injection_command_endpoint_level(inj, url)
    if result is not None:
        return result
    # Fallback
    return f"http(action='request', url='{url}', method='{method}')"


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

_RECON_ONLY_TOOLS = {"naabu", "subfinder", "nmap"}
_EXPLOITATION_TOOLS = {"kali_sqlmap", "kali"}  # kali used for sqlmap/hydra/etc


def _detect_drift(tool: str, phase: str, tools_run: set) -> list[str]:
    """Detect behavioral drift and return warning strings."""
    warnings: list[str] = []

    # Exploitation during recon
    if phase == "recon" and tool in _EXPLOITATION_TOOLS:
        warnings.append(
            f"DRIFT: Running {tool} during recon phase. "
            f"Complete discovery first: httpx → spider → register endpoints → then test."
        )

    # Recon tool during testing (going backwards)
    if phase == "testing" and tool in _RECON_ONLY_TOOLS:
        warnings.append(
            f"DRIFT: Running {tool} during testing phase. "
            f"Recon is already complete. Focus on pending coverage cells."
        )

    # httpx not run but trying to spider/test
    if tool == "spider" and "httpx" not in tools_run:
        warnings.append(
            "DRIFT: Spider called before httpx. Run httpx first to confirm target is live."
        )

    return warnings
