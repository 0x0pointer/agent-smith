"""AI red-team data store — the dashboard's AI Red Team tab reads this.

Holds the AI-specific signal that the generic findings/coverage stores don't
capture in a dashboard-friendly shape:
  * garak       — per probe/detector attack-success rates
  * filter      — which encodings the target's input filter lets through
  * calibration — canary self-test status (is the engine trustworthy?)
  * attacks     — feedback-loop transcripts + k/N reproducibility

The OWASP coverage GRID and per-finding k/N are derived on the client from the
existing /api/coverage and /api/findings, so those aren't duplicated here.

Fail-soft: recording never raises into a tool call; a write error is swallowed.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

from core import paths as _paths

_FILE = _paths.AI_REDTEAM_FILE
_LOCK = threading.Lock()
_MAX_ATTACKS = 50
_MAX_GARAK = 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    try:
        return json.loads(_FILE.read_text()) if _FILE.exists() else {}
    except Exception:
        return {}


def _empty() -> dict:
    return {"garak": [], "filter": None, "calibration": None, "attacks": [], "updated_at": None}


def _save(doc: dict) -> None:
    doc["updated_at"] = _now()
    try:
        _FILE.write_text(json.dumps(doc, indent=2))
    except Exception:
        pass


def get() -> dict:
    doc = _load()
    if not doc:
        return _empty()
    for k, v in _empty().items():
        doc.setdefault(k, v)
    return doc


def _eval_from_line(line: str) -> dict | None:
    """Parse one garak report.jsonl line into an eval summary, or None if it isn't
    a well-formed ``eval`` entry."""
    line = line.strip()
    if not line.startswith("{") or '"eval"' not in line:
        return None
    try:
        d = json.loads(line)
    except Exception:
        return None
    if d.get("entry_type") != "eval":
        return None
    total = d.get("total_evaluated", d.get("total", 0)) or 0
    fails = d.get("fails")
    if fails is None:
        fails = (total - (d.get("passed", 0) or 0)) if total else 0
    rate = round(fails / total, 4) if total else 0.0
    return {"probe": d.get("probe", "?"), "detector": d.get("detector", "?"),
            "fails": fails, "total": total, "attack_success_rate": rate}


def _parse_garak_evals(raw: str) -> list[dict]:
    """Extract garak 0.15.0 eval entries (probe/detector/fails/total_evaluated)
    from the report section, and compute an attack-success rate per detector."""
    marker = "=== GARAK REPORT JSONL ==="
    idx = raw.find(marker)
    section = raw[idx + len(marker):] if idx != -1 else raw
    out = []
    for line in section.splitlines():
        e = _eval_from_line(line)
        if e is not None:
            out.append(e)
    return out


def record_garak_from_raw(raw: str, target: str = "") -> None:
    """Record garak eval rows, UPSERTING on (target, probe, detector).

    Upsert (not append) so live streaming — which calls this repeatedly with a
    growing partial report during one run — refines each probe/detector row in
    place instead of piling up duplicates, and so a re-run on the same target
    overwrites its old numbers rather than doubling them."""
    evals = _parse_garak_evals(raw or "")
    if not evals:
        return
    now = _now()
    with _LOCK:
        doc = get()
        rows = doc["garak"]
        index = {(r.get("target"), r.get("probe"), r.get("detector")): i
                 for i, r in enumerate(rows)}
        for e in evals:
            e["target"] = target
            e["ts"] = now
            key = (target, e.get("probe"), e.get("detector"))
            if key in index:
                rows[index[key]] = e            # refine in place
            else:
                index[key] = len(rows)
                rows.append(e)
        doc["garak"] = rows[-_MAX_GARAK:]
        _save(doc)


def record_filter_probe(result: dict, target: str = "") -> None:
    with _LOCK:
        doc = get()
        doc["filter"] = {**(result or {}), "target": target, "ts": _now()}
        _save(doc)


def record_calibration(result: dict) -> None:
    with _LOCK:
        doc = get()
        doc["calibration"] = {**(result or {}), "ts": _now()}
        _save(doc)


def record_attack(result: dict, goal: str = "", target: str = "") -> None:
    """Store a feedback_attack transcript summary (trimmed for the dashboard)."""
    with _LOCK:
        doc = get()
        entry = {
            "ts": _now(), "target": target, "goal": goal,
            "jailbroken": bool(result.get("jailbroken")),
            "attempts": result.get("attempts"),
            "best": result.get("best"),
            "reproducibility": result.get("reproducibility"),
            "transcript": (result.get("transcript") or [])[:12],
        }
        doc["attacks"] = (doc["attacks"] + [entry])[-_MAX_ATTACKS:]
        _save(doc)


def reset() -> None:
    with _LOCK:
        _save(_empty())


# ── Toolchain readiness ───────────────────────────────────────────────────────
# "Is the AI red-team toolchain (engines + garak + the MCP tools) actually
# available/working?" — shown on the dashboard so the operator knows the
# capability is live, not whether a labs self-test passed. Cached: the docker
# probe is spawned at most once per _HEALTH_TTL seconds.
import subprocess  # noqa: E402
import time  # noqa: E402

_HEALTH_TTL = 30
_HEALTH_CACHE: dict = {"ts": 0.0, "data": None}
_MCP_REQUIRED = ["scan", "transform", "redteam", "http", "report", "session"]


def _docker_image_exists(image: str) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, timeout=6)
        return r.returncode == 0
    except Exception:
        return False


def _registered_mcp_tools() -> set:
    """Tools the running MCP server exposes.

    Reads the LIVE in-memory FastMCP registry first — the readiness check runs
    inside the server process, so `@mcp.tool()` registrations are already present,
    and this is IMMUNE to a dashboard "Clear logs" that deletes
    logs/tools_registered.log (that file is written once at startup and never
    rewritten, so a mid-run clear would otherwise fail this check and block the
    whole AI red-team assessment). Falls back to the startup audit log only if the
    live read fails."""
    # 1) live registry (authoritative, survives a cleared logs/ dir)
    try:
        from mcp_server._app import mcp
        # Ensure the dispatch modules are imported so their @mcp.tool() decorators
        # have run in this process (idempotent if already loaded).
        for _m in ("scan_tools", "http_tools", "report_tools", "session_tools",
                   "transform_tools", "redteam_tools"):
            try:
                __import__(f"mcp_server.{_m}")
            except Exception:
                pass
        names = {t.name for t in mcp._tool_manager.list_tools()}
        if names:
            return names
    except Exception:
        pass
    # 2) fallback: the startup audit log (absent after a logs clear)
    try:
        p = _paths.LOGS_DIR / "tools_registered.log"
        txt = p.read_text() if p.exists() else ""
        return {ln.split("REGISTERED:", 1)[1].strip()
                for ln in txt.splitlines() if "REGISTERED:" in ln}
    except Exception:
        return set()


def toolchain_status() -> dict:
    """Component-by-component readiness of the AI red-team toolchain."""
    now = time.time()
    cached = _HEALTH_CACHE.get("data")
    if cached and (now - _HEALTH_CACHE["ts"]) < _HEALTH_TTL:
        return cached

    comps = []
    # payload-crafting engine (pure-Python)
    try:
        from mcp_server.transforms import TRANSFORMS
        comps.append({"name": "transform() engine", "ok": True,
                      "detail": f"{len(TRANSFORMS)} transforms loaded"})
    except Exception as e:
        comps.append({"name": "transform() engine", "ok": False, "detail": str(e)[:70]})
    # manual-layer engine
    try:
        from mcp_server.redteam.techniques import technique_count
        c = technique_count()
        comps.append({"name": "redteam() engine", "ok": True,
                      "detail": f"{c['unique']} executable techniques "
                                f"({c['tuned']} tuned + {c['pitax']} PITAX)"})
    except Exception as e:
        comps.append({"name": "redteam() engine", "ok": False, "detail": str(e)[:70]})
    # garak automated scanner image
    gk = _docker_image_exists("pentest-agent/garak")
    comps.append({"name": "garak image", "ok": gk,
                  "detail": "pentest-agent/garak built" if gk
                            else "not built yet — auto-builds on first scan(tool=\"garak\")"})
    # MCP tools registered by the running daemon
    tools = _registered_mcp_tools()
    have = [t for t in _MCP_REQUIRED if t in tools]
    mcp_ok = len(have) == len(_MCP_REQUIRED)
    comps.append({"name": "MCP tools", "ok": mcp_ok,
                  "detail": (f"{len(have)}/{len(_MCP_REQUIRED)} registered: {', '.join(have)}" if tools
                             else "no MCP tools registered — the pentest-agent server isn't loaded")})

    # garak "not built" is non-blocking (auto-builds), so it doesn't fail readiness.
    blocking = [c for c in comps if c["name"] != "garak image"]
    data = {"ready": all(c["ok"] for c in blocking), "components": comps}
    _HEALTH_CACHE.update(ts=now, data=data)
    return data


# ── Attack-taxonomy overview (Arcanum PITAX) ────────────────────────────────────
# Static reference the AI Red Team tab shows in its Overview: the PITAX pillars +
# how the engine maps onto them (technique families -> PIT-T, transforms -> PIT-E).
# The data never changes at runtime, so it is cached for the process lifetime.
_TAX_CACHE: dict = {"data": None, "done": False}


def taxonomy_overview() -> dict | None:
    if _TAX_CACHE["done"]:
        return _TAX_CACHE["data"]
    data = None
    try:
        from mcp_server.redteam import taxonomy as _tax
        from mcp_server.redteam.techniques import TECHNIQUES, technique_count
        from mcp_server.transforms import TRANSFORMS
        pillars = _tax.pillars()
        # Chips show the hand-tuned core (the 13); the full arsenal size is in `executable`.
        families = [{"name": t.name, "pit": t.pit, "category": t.category}
                    for t in TECHNIQUES.values()]
        data = {
            "source": "Arcanum Prompt Injection Taxonomy (PITAX)",
            "license": "CC BY 4.0",
            "url": "https://github.com/Arcanum-Sec/arc_pi_taxonomy",
            "total": sum(p["count"] for p in pillars.values()),
            "pillars": pillars,
            "engine": {
                "technique_families": families,
                "families_mapped": len(families),
                "transforms": len(TRANSFORMS),
                "executable": technique_count(),
            },
        }
    except Exception:
        data = None
    _TAX_CACHE.update(data=data, done=True)
    return data
