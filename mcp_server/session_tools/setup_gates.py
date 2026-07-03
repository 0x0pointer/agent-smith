"""Manual-setup gate lifecycle (capabilities.yaml prerequisites)."""
import json

from core import logger as log
from core import session as scan_session


# ── Manual-setup gates (capabilities.yaml prerequisites) ───────────────────────
# Non-blocking lifecycle for a manual/physical prerequisite a skill declares:
# open (usually automatic on set_skill) → elect (now|defer|skip) → check (run the
# allow-listed readiness probe). NEVER blocks session(complete) — distinct from the
# skill-chaining gates in core/session/gates.py.

def _setup_gate_describe(gate: dict, opened: bool = False) -> str:
    gid = gate["id"]
    host_note = " [requires_host — needs explicit human opt-in once/session]" if gate.get("requires_host") else ""
    steps = gate.get("runbook") or []
    runbook_txt = "\n".join(
        f"  {i + 1}. {s.get('step', '')}" + (f"   [$ {s['command']}]" if s.get("command") else "")
        for i, s in enumerate(steps)
    ) or "  (no runbook steps declared)"
    return (
        f"{'Opened' if opened else 'Setup gate'} '{gid}' ({gate.get('category', 'other')}){host_note} "
        f"— status {gate.get('status')}.\n{gate.get('description', '')}\n"
        f"Runbook:\n{runbook_txt}\n\n"
        f"ELECT: interactive → ASK the operator whether to set this up now; headless → default 'defer'. "
        f"session(action='setup_gate', options={{'action':'elect','id':'{gid}','choice':'now|defer|skip'}}). "
        f"After setup, verify: options={{'action':'check','id':'{gid}'}}."
    )


def _setup_gate_list_response() -> str:
    gates = scan_session.list_setup_gates()
    return json.dumps({
        "count": len(gates),
        "gates": [
            {
                "id": g["id"], "category": g.get("category"), "status": g.get("status"),
                "election": g.get("election"), "requires_host": g.get("requires_host"),
                "skill": g.get("skill"), "description": g.get("description", ""),
                "probe_verb": (g.get("readiness_probe") or {}).get("verb"),
                "probe_ok": (g.get("probe_result") or {}).get("ok"),
            }
            for g in gates
        ],
    }, indent=2)


async def _setup_gate_check(gid: str) -> str:
    from core import probe_runner
    from mcp_server.scan_engine.artifacts import store_artifact

    def _store(res):
        return store_artifact("probe", json.dumps({"gate": gid, "result": res}, indent=2, default=str))

    out = await probe_runner.check_gate(gid, artifact_store=_store)
    status = out["status"]
    if status == "no_gate":
        return f"No setup gate '{gid}' found. List gates with options={{'action':'list'}}."
    if status == "skipped":
        return f"Gate '{gid}' was skipped by the operator — not probing. Re-elect 'now' to test it."
    if status == "no_probe":
        return f"Gate '{gid}' has no readiness_probe — confirm setup manually; this gate cannot be auto-verified."

    res = out["result"]
    artifact_id = out["artifact_id"]
    if status == "ok":
        return json.dumps({
            "gate": gid, "status": "satisfied", "probe_ok": True,
            "artifact_id": artifact_id, "device": res.get("device"),
            "next": "Setup confirmed live by the readiness probe — proceed with the gated phase.",
        }, indent=2, default=str)

    return json.dumps({
        "gate": gid, "status": "failed", "probe_ok": False, "artifact_id": artifact_id,
        "ran": res.get("ran"), "exit_code": res.get("exit_code"),
        "stdout_excerpt": (res.get("stdout") or "")[:300],
        "reason": res.get("error") or "readiness-probe success criterion not met",
        "next": ("Setup not ready. Re-check the runbook and re-run setup_gate check. If it cannot be set "
                 "up, elect 'skip' and mark dependent cells skipped (reason: operator declined manual setup)."),
    }, indent=2, default=str)


def _setup_gate_open(opts: dict) -> str:
    cap = opts.get("capability")
    if not isinstance(cap, dict) or not cap.get("id"):
        return ("setup_gate open needs options.capability={id,...}. Gates are usually opened "
                "automatically from a skill's capabilities.yaml on set_skill — manual open is rarely needed.")
    gate = scan_session.open_setup_gate(cap, skill=str(opts.get("skill", "")))
    if gate is None:
        return "No active running session — cannot open a setup gate."
    return _setup_gate_describe(gate, opened=True)


_SETUP_ELECT_MSG = {
    "now": ("Gate '{gid}' elected NOW. Run the runbook steps, then verify with "
            "session(action='setup_gate', options={{'action':'check','id':'{gid}'}})."),
    "defer": ("Gate '{gid}' DEFERRED (non-blocking) — surfaced on the dashboard for the operator. "
              "Keep testing other coverage; re-check later or let the operator fulfill it."),
    "skip": ("Gate '{gid}' SKIPPED — mark its dependent cells skipped with reason "
             "'operator declined manual setup'. Recorded so the gap is explicit in the report."),
}


def _setup_gate_elect(opts: dict) -> str:
    gid = str(opts.get("id", "")).strip()
    choice = str(opts.get("choice", "")).strip()
    if not gid or choice not in _SETUP_ELECT_MSG:
        return "setup_gate elect requires options.id and options.choice ∈ now|defer|skip."
    gate = scan_session.record_election(gid, choice)
    if gate is None:
        return f"No setup gate '{gid}' found (or no running session)."
    log.note(f"setup_gate {gid} elected: {choice}")
    return _SETUP_ELECT_MSG[choice].format(gid=gid)


async def _do_setup_gate(opts: dict) -> str:
    """Manual-setup prerequisite lifecycle. options.action ∈ open|list|elect|check.

    Non-blocking: an unsatisfied gate never blocks session(complete); it leaves
    dependent work in a clearly-marked skipped state and the scan still completes.
    """
    sub = str(opts.get("action") or "list").strip()
    if sub == "list":
        return _setup_gate_list_response()
    if sub == "open":
        return _setup_gate_open(opts)
    if sub == "elect":
        return _setup_gate_elect(opts)
    if sub == "check":
        gid = str(opts.get("id", "")).strip()
        if not gid:
            return "setup_gate check requires options.id."
        return await _setup_gate_check(gid)
    return "setup_gate: options.action must be one of open|list|elect|check."
