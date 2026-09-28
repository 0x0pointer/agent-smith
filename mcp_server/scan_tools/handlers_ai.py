"""AI red-team handler: garak (probe-based LLM scanning).

garak now runs in its own standalone image (pentest-agent/garak) via
tools/garak_runner.py — moved out of the Kali image (which it bloated to ~20 GB
via torch) so Kali stays lean and garak is versioned/built independently.

Automated coverage is garak; everything it does not cover is handled by
agent-driven manual testing with the transform() payload tool.
"""
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

async def _handle_garak(target, flags, options):
    from tools import garak_runner

    _record("garak")  # track for coverage/skill-worked gates
    probes     = options.get("probes", "dan,encoding,promptinject,leakreplay,xss")
    timeout    = options.get("timeout", 900)
    body_key   = options.get("body_key", "message")
    method     = options.get("method", "post")
    resp_field = options.get("response_field", "")  # JSONPath to the reply text

    # garak 0.15.0 wants canonical probe names WITHOUT a "probes." prefix:
    # both "dan" and "dan.Dan_11_0" are accepted, but "probes.dan[.Class]" is
    # REJECTED ("Unknown probes" -> garak runs nothing). Strip any stray prefix;
    # never add one.
    qualified = ",".join(
        p[len("probes."):] if p.startswith("probes.") else p
        for p in (s.strip() for s in probes.split(",")) if p
    )

    # REST-generator config (-G). Provides the request body ($INPUT slot) and, if
    # given, the response parser — without both, every probe scores empty output.
    # Rewrite localhost/127.0.0.1 → host.docker.internal so the garak container
    # (bridge net + --add-host=host-gateway) reaches a target on the host — works
    # on macOS AND Linux (--network=host does not, on Docker Desktop).
    from tools.kali_runner import _host_rewrite
    gen = {
        "name":    "agent-smith-target",
        "uri":     _host_rewrite(target),
        "method":  method,
        "headers": _ai_headers(options),
        "req_template_json_object": {body_key: "$INPUT"},
    }
    if resp_field:
        gen["response_json"] = True
        gen["response_json_field"] = resp_field
    rest_cfg = {"rest": {"RestGenerator": gen}}

    log.tool_call("garak", {"target": target, "probes": qualified})
    call_id = cost_tracker.start("garak")
    raw = _clip(await garak_runner.run_garak(rest_cfg, qualified, flags=flags, timeout=timeout), 14_000)
    cost_tracker.finish(call_id, raw)
    log.tool_result("garak", raw)
    from mcp_server.scan_engine import wrap
    return wrap("garak", raw, {"target": target, "probes": qualified})
