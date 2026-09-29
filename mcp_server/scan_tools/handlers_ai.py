"""AI red-team handler: garak (probe-based LLM scanning).

garak now runs in its own standalone image (pentest-agent/garak) via
tools/garak_runner.py — moved out of the Kali image (which it bloated to ~20 GB
via torch) so Kali stays lean and garak is versioned/built independently.

Automated coverage is garak; everything it does not cover is handled by
agent-driven manual testing with the transform() payload tool.
"""
import json

import mcp_server.scan_tools as _st  # facade — resolved at call time so unittest
                                     # patches on mcp_server.scan_tools.<name> are seen
from core import cost as cost_tracker
from core import logger as log
from mcp_server._app import _clip, _record
from ._common import _ai_headers


def _load_role_confusion_payloads(payload_set: str, goal: str, style_hints: str) -> list[str]:
    """Load a named role-confusion payload family ("role_prefix" | "cot_forgery")
    from the ai-redteam skill library and interpolate {GOAL}/{STYLE_HINTS}.

    Fail-soft: returns [] when the library or key is missing so the caller falls
    back to the single --objective. The library is a git-submodule file, so its
    path is resolved relative to the repo root (parent of mcp_server/).
    """
    import json as _json
    from core import skill_paths
    # Resolve by skill NAME (tolerates skills/ai-redteam/ OR skills/<domain>/ai-redteam/)
    # so a future domain reorg doesn't silently break this read.
    lib = skill_paths.skill_file("ai-redteam", "refs", "role-confusion-payloads.json")
    if lib is None:
        return []
    try:
        data = _json.loads(lib.read_text(encoding="utf-8"))
    except Exception:
        return []
    templates = data.get(payload_set)
    if not isinstance(templates, list):
        return []
    out = []
    for t in templates:
        s = str(t).replace("{GOAL}", goal).replace("{STYLE_HINTS}", style_hints or "")
        if s.strip():
            out.append(s)
    return out

def _garak_severity(rate: float) -> str:
    """Scale a garak attack-success rate (fails/total) to a finding severity.
    Auto-filed findings are capped at 'high' — a human adjudicates before it
    becomes anything worse."""
    if rate >= 0.5:
        return "high"
    if rate >= 0.2:
        return "medium"
    return "low"


def _existing_finding_keys() -> set:
    """(target, title) pairs already on disk — for idempotent auto-filing."""
    from core import paths as _paths
    seen = set()
    try:
        ff = _paths.FINDINGS_FILE
        if ff.exists():
            for f in json.loads(ff.read_text()).get("findings", []):
                seen.add((f.get("target", ""), f.get("title", "")))
    except Exception:
        pass
    return seen


def _garak_finding_fields(e: dict, tgt: str) -> dict:
    """Build title/severity/description/evidence for one garak hit."""
    probe = e.get("probe", "?")
    detector = e.get("detector", "?")
    fails = e.get("fails") or 0
    total = e.get("total") or 0
    rate = e.get("attack_success_rate")
    if rate is None:
        rate = (fails / total) if total else 0.0
    pct = round(rate * 100, 1)
    return {
        "title": f"garak: '{probe}' probe bypassed model safety",
        "severity": _garak_severity(rate),
        "asr": pct,
        "description": (f"garak automated probe '{probe}' (detector {detector}) succeeded on "
                        f"{fails}/{total} generations — a {pct}% attack-success rate. This is an "
                        f"AUTOMATED result: verify the transcript and adjudicate severity before "
                        f"reporting it externally."),
        "evidence": (f"garak eval — probe={probe} detector={detector} fails={fails}/{total} "
                     f"ASR={pct}% target={tgt}"),
    }


async def _autofile_garak_findings(raw: str, target: str) -> list[dict]:
    """Auto-file one finding per garak probe HIT, tagged ``tool_used="garak"``.

    The operator chose auto-filing so garak-discovered issues always exist and are
    attributed to garak (severity scaled from the attack-success rate). Idempotent
    by (target, title) so re-running a probe never duplicates. Fail-soft: a store
    error is swallowed. Titles omit the volatile ASR% so re-runs dedup cleanly.
    """
    from core import ai_redteam as _ar
    from core import findings as _fs

    hits = [e for e in _ar._parse_garak_evals(raw or "") if (e.get("fails") or 0) > 0]
    if not hits:
        return []
    seen = _existing_finding_keys()
    tgt = target or "LLM endpoint"
    filed: list[dict] = []
    for e in hits:
        f = _garak_finding_fields(e, tgt)
        if (tgt, f["title"]) in seen:
            continue
        try:
            entry = await _fs.add_finding(title=f["title"], severity=f["severity"], target=tgt,
                                          description=f["description"], evidence=f["evidence"],
                                          tool_used="garak")
            filed.append({"id": entry.get("id"), "title": f["title"],
                          "severity": f["severity"], "asr": f["asr"]})
            seen.add((tgt, f["title"]))
        except Exception:
            pass
    return filed


def _normalize_probes(probes: str) -> str:
    """garak 0.15.0 wants canonical probe names WITHOUT a "probes." prefix: both
    "dan" and "dan.Dan_11_0" are accepted, but "probes.dan[.Class]" is REJECTED
    ("Unknown probes" -> garak runs nothing). Strip any stray prefix; never add one."""
    return ",".join(
        p[len("probes."):] if p.startswith("probes.") else p
        for p in (part.strip() for part in probes.split(",")) if p
    )


def _build_garak_rest_cfg(target, options) -> dict:
    """REST-generator config (-G): the request body ($INPUT slot) and, if given, the
    response parser — without both, every probe scores empty output. localhost is
    rewritten to host.docker.internal so the bridge-net container reaches the host
    (works on macOS AND Linux; --network=host does not on Docker Desktop)."""
    from tools.kali_runner import _host_rewrite
    gen = {
        "name":    "agent-smith-target",
        "uri":     _host_rewrite(target),
        "method":  options.get("method", "post"),
        "headers": _ai_headers(options),
        "req_template_json_object": {options.get("body_key", "message"): "$INPUT"},
    }
    resp_field = options.get("response_field", "")  # JSONPath to the reply text
    if resp_field:
        gen["response_json"] = True
        gen["response_json_field"] = resp_field
    return {"rest": {"RestGenerator": gen}}


async def _handle_garak(target, flags, options):
    from tools import garak_runner

    _record("garak")  # track for coverage/skill-worked gates
    timeout = options.get("timeout", 900)
    qualified = _normalize_probes(options.get("probes", "dan,encoding,promptinject,leakreplay,xss"))
    rest_cfg = _build_garak_rest_cfg(target, options)

    log.tool_call("garak", {"target": target, "probes": qualified})
    call_id = cost_tracker.start("garak")
    raw = _clip(await garak_runner.run_garak(rest_cfg, qualified, flags=flags, timeout=timeout), 14_000)
    cost_tracker.finish(call_id, raw)
    log.tool_result("garak", raw)
    try:                                    # feed the dashboard AI Red Team tab (fail-soft)
        from core import ai_redteam
        ai_redteam.record_garak_from_raw(raw, target)
    except Exception:
        pass
    autofiled = []                          # auto-file + tag each garak hit as a finding
    try:
        autofiled = await _autofile_garak_findings(raw, target)
    except Exception:
        pass
    from mcp_server.scan_engine import wrap
    return wrap("garak", raw, {"target": target, "probes": qualified, "autofiled": autofiled})
