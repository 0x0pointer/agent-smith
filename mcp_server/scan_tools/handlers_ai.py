"""AI red-team handlers: fuzzyai, garak, promptfoo."""
import shlex

import mcp_server.scan_tools as _st  # facade — resolved at call time so unittest
                                     # patches on mcp_server.scan_tools.<name> are seen
from core import cost as cost_tracker
from core import logger as log
from mcp_server._app import _clip, _record, _run
from ._common import (
    _ai_auth_headers,
    _ai_headers,
    _kali_scratch_dir,
    _kali_target_url,
    _stage_file_cmd,
)


async def _handle_fuzzyai(target, flags, options):
    # FuzzyAI runs as its own Docker image (ghcr.io/cyberark/fuzzyai) via docker_runner,
    # NOT inside the Kali container — it is not installed in the Kali Dockerfile.
    _record("fuzzyai")
    attack   = options.get("attack",   "jailbreak")
    provider = options.get("provider", "openai")
    model    = options.get("model",    "")
    raw = await _run("fuzzyai", target=target, attack=attack, provider=provider, model=model, flags=flags)
    from mcp_server.scan_engine import wrap
    return wrap("fuzzyai", raw, {"target": target, "attack": attack})


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
    from tools import kali_runner
    import json as _json

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

    url = _kali_target_url(target)
    gen = {
        "name":    "agent-smith-target",
        "uri":     url,
        "method":  method,
        "headers": _ai_headers(options),
        "req_template_json_object": {body_key: "$INPUT"},
    }
    if resp_field:
        gen["response_json"] = True
        gen["response_json_field"] = resp_field
    rest_cfg = {"rest": {"RestGenerator": gen}}

    scratch  = _kali_scratch_dir()
    cfg_path = f"{scratch}/garak_rest.json"
    prefix   = f"{scratch}/garak_run"
    stage = _stage_file_cmd(_json.dumps(rest_cfg), cfg_path)
    # Garak's REST generator is config-driven (-G). The old invocation passed
    # only `--generator_option api_base=<url>`, which defined neither a request
    # body (no $INPUT slot) nor a response parser, so every probe scored empty
    # output. The JSON config above supplies both.
    garak_cmd = (
        f"garak --target_type rest -G {cfg_path}"
        f" --probes {shlex.quote(qualified)}"
        f" --report_prefix {prefix}"
    )
    if flags:
        garak_cmd += f" {shlex.join(shlex.split(flags))}"
    # Append the structured per-probe report so the summarizer can extract hits.
    full = (
        f"mkdir -p {shlex.quote(scratch)} && {stage} && {garak_cmd}; "
        f"echo '=== GARAK REPORT JSONL ==='; "
        f"tail -n 300 {prefix}.report.jsonl 2>/dev/null"
    )

    log.tool_call("garak", {"target": target, "probes": qualified})
    call_id = cost_tracker.start("garak")
    raw = _clip(await kali_runner.exec_command(full, timeout=timeout), 14_000)
    cost_tracker.finish(call_id, raw)
    log.tool_result("garak", raw)
    from mcp_server.scan_engine import wrap
    return wrap("garak", raw, {"target": target, "probes": qualified})


async def _handle_promptfoo(target, flags, options):
    from tools import kali_runner
    import json as _json

    plugins    = options.get("plugins", "prompt-injection,excessive-agency,pii,hallucination,prompt-extraction")
    strategies = options.get("attack_strategies", "jailbreak,crescendo")
    timeout    = options.get("timeout", 900)
    body_key   = options.get("body_key", "prompt")
    method     = options.get("method", "POST")
    resp_field = options.get("response_field", "")        # transformResponse expr
    attacker   = options.get("attacker_provider", "")     # redteam.provider (attacker LLM)

    url = _kali_target_url(target)
    provider = {
        "id": "https",
        "config": {
            "url":     url,
            "method":  method,
            "headers": _ai_headers(options),
            "body":    {body_key: "{{prompt}}"},
        },
    }
    if resp_field:
        provider["config"]["transformResponse"] = resp_field
    config = {
        "targets": [provider],
        "redteam": {
            "plugins":    [p.strip() for p in plugins.split(",") if p.strip()],
            "strategies": [s.strip() for s in strategies.split(",") if s.strip()],
        },
    }
    if attacker:
        config["redteam"]["provider"] = attacker

    scratch  = _kali_scratch_dir()
    cfg_path = f"{scratch}/promptfooconfig.json"
    gen_path = f"{scratch}/promptfoo_redteam.yaml"
    out_path = f"{scratch}/promptfoo_out.json"
    stage = _stage_file_cmd(_json.dumps(config), cfg_path)
    # Config-driven two-step (verified against promptfoo 0.121.2): `redteam
    # generate` writes adversarial test cases (needs an attacker-LLM key via
    # redteam.provider / OPENAI_API_KEY), then `eval -o` runs them against the
    # target and writes the RESULTS JSON. NOTE: for `redteam run`, `-o` is the
    # generated-tests file (NOT results) — that's why we split the steps and read
    # results from `eval -o`. The old `--target/--plugins/--strategies` flags
    # weren't valid for the config-driven pipeline at all.
    gen_cmd  = f"promptfoo redteam generate -c {cfg_path} -o {gen_path}"
    eval_cmd = f"promptfoo eval -c {gen_path} -o {out_path}"
    if flags:
        eval_cmd += f" {shlex.join(shlex.split(flags))}"
    full = (
        f"mkdir -p {shlex.quote(scratch)} && {stage} && {gen_cmd} && {eval_cmd}; "
        f"echo '=== PROMPTFOO RESULTS JSON ==='; "
        f"cat {out_path} 2>/dev/null"
    )

    log.tool_call("promptfoo", {"target": target, "plugins": plugins, "strategies": strategies})
    call_id = cost_tracker.start("promptfoo")
    raw = _clip(await kali_runner.exec_command(full, timeout=timeout), 14_000)
    cost_tracker.finish(call_id, raw)
    log.tool_result("promptfoo", raw)
    from mcp_server.scan_engine import wrap
    return wrap("promptfoo", raw, {"target": target, "plugins": plugins})
