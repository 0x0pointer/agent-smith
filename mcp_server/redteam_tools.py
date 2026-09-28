"""Consolidated manual-layer red-team tool — `redteam()`.

Exposes the mcp_server.redteam engine to the agent: the curated technique library,
adaptive filter-probing, the feedback-guided (PAIR/TAP-style) attack loop with
built-in k/N reproducibility, the oracle/judge, and the canary calibration.

Pure-Python + HTTP (via urllib, run off-thread). No API key needed for the core;
pass options.model_* to enable the LLM-judge/attacker later.

Typical use inside /ai-redteam:
  redteam(action="calibrate", target="http://labs:9000")             # trust the harness
  redteam(action="filter_probe", target=URL)                        # learn bypasses
  redteam(action="feedback_attack", target=URL,
          options={"goal":"leak the system prompt","success_markers":["SECRET"],
                   "reproduce_n":10})
"""
from __future__ import annotations

import asyncio
import json
import urllib.request

from core import logger as log
from mcp_server._app import mcp, _ensure_dict, _record
from mcp_server import redteam as _rt
from mcp_server.redteam import calibration as _cal
from mcp_server.redteam import filter_probe as _fp
from mcp_server.redteam import oracles as _or


def _record_ai(fn) -> None:
    """Persist a result into the AI red-team store (feeds the dashboard tab). Fail-soft."""
    try:
        from core import ai_redteam
        fn(ai_redteam)
    except Exception:
        pass


def _http_send_fn(target: str, body_key: str, reply_key: str, headers: dict | None):
    hdrs = {"Content-Type": "application/json", **(headers or {})}

    def send(message: str, conversation_id: str | None = None) -> str:
        body = {body_key: message}
        if conversation_id:
            body["conversation_id"] = conversation_id
        req = urllib.request.Request(target, json.dumps(body).encode(), hdrs)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
                return data.get(reply_key, json.dumps(data)) if isinstance(data, dict) else str(data)
        except Exception as e:
            return f"[send error: {e}]"
    return send


@mcp.tool()
async def redteam(action: str, target: str = "", options: dict | str | None = None) -> str:
    """Manual-layer red-team engine (technique library, filter-probe, feedback loop, judge, calibration).

    action : techniques | filter_probe | feedback_attack | judge | calibrate | taxonomy
    target : the LLM endpoint URL (POST JSON); for calibrate, the labs base URL
    options:
      techniques      — category=single_turn|multi_turn|structural
      filter_probe    — body_key=message, reply_key=reply, headers={}
      feedback_attack — goal (required), success_markers=[...], transforms=[...],
                        max_attempts=24, seed=0, reproduce_n=0, body_key=, reply_key=, headers={}
      judge           — text, goal, success_markers=[...]
      calibrate       — (target = labs base URL, default http://127.0.0.1:9000)
      taxonomy        — Arcanum PITAX reference. pillar=intents|techniques|evasions|inputs,
                        code=PIT-x-NN (full node), query=<text> (search). No args = overview.
    """
    opts = _ensure_dict(options) or {}
    _record("redteam")   # count as AI red-team work for coverage/skill gates
    log.tool_call("redteam", {"action": action, "target": target, "options": opts})
    try:
        result = await asyncio.to_thread(_dispatch, action, target, opts)
    except Exception as exc:      # fail-soft
        result = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    log.tool_result("redteam", result)
    return result


def _do_techniques(target, opts):
    return json.dumps({"techniques": _rt.list_techniques(opts.get("category"))}, indent=2)


def _do_taxonomy(target, opts):
    tax = _rt.taxonomy
    if opts.get("code"):
        node = tax.lookup(opts["code"])
        return json.dumps({"node": node} if node
                          else {"error": f"no PITAX node '{opts['code']}'"}, indent=2)
    if opts.get("query"):
        return json.dumps({"results": tax.search(opts["query"], int(opts.get("limit", 25)))}, indent=2)
    if opts.get("pillar"):
        return json.dumps({"pillar": opts["pillar"], "nodes": tax.nodes(opts["pillar"])}, indent=2)
    return json.dumps({"source": "Arcanum PITAX (CC BY 4.0)", "pillars": tax.pillars(),
                       "usage": "options={pillar|code|query}"}, indent=2)


def _do_judge(target, opts):
    v = _or.llm_judge(opts.get("text", ""), opts.get("goal", ""),
                      success_markers=opts.get("success_markers"))
    return json.dumps(v.__dict__, indent=2)


def _do_calibrate(target, opts):
    cal = _cal.calibrate(target or "http://127.0.0.1:9000")
    _record_ai(lambda ar: ar.record_calibration(cal))
    return json.dumps(cal, indent=2)


def _do_filter_probe(target, opts):
    if not target:
        return json.dumps({"error": "filter_probe requires target=<URL>"})
    send = _http_send_fn(target, opts.get("body_key", "message"),
                         opts.get("reply_key", "reply"), opts.get("headers"))
    res = _fp.probe_filter(send)
    _record_ai(lambda ar: ar.record_filter_probe(res, target))
    return json.dumps(res, indent=2)


def _do_feedback_attack(target, opts):
    if not target or not opts.get("goal"):
        return json.dumps({"error": "feedback_attack requires target=<URL> and options.goal"})
    send = _http_send_fn(target, opts.get("body_key", "message"),
                         opts.get("reply_key", "reply"), opts.get("headers"))
    goal = opts["goal"]
    markers = opts.get("success_markers")
    r = _rt.feedback_attack(goal, send, success_markers=markers,
                            transforms=opts.get("transforms"),
                            max_attempts=int(opts.get("max_attempts", 24)),
                            seed=int(opts.get("seed", 0)))
    n = int(opts.get("reproduce_n", 0) or 0)
    if r["jailbroken"] and n:
        # Replay the EXACT winning payload — the only way k/N measures the model's
        # non-determinism rather than our (now creative/variant) render variance.
        winning = (r.get("best") or {}).get("payload") or ""

        def one_shot():
            reply = send(winning if isinstance(winning, str) else winning[-1])
            return _or.heuristic_judge(reply, goal, markers)
        r["reproducibility"] = _rt.reproduce(one_shot, n=n)
    r["transcript"] = r["transcript"][:12]   # trim for context
    _record_ai(lambda ar: ar.record_attack(r, goal, target))
    return json.dumps(r, indent=2)


_DISPATCH = {"techniques": _do_techniques, "taxonomy": _do_taxonomy, "judge": _do_judge,
             "calibrate": _do_calibrate, "filter_probe": _do_filter_probe,
             "feedback_attack": _do_feedback_attack}


def _dispatch(action: str, target: str, opts: dict) -> str:
    fn = _DISPATCH.get(action)
    if fn is None:
        return json.dumps({"error": f"unknown action '{action}'. Use: " + ", ".join(_DISPATCH)})
    return fn(target, opts)
