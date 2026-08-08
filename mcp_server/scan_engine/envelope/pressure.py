"""
P4 — Context-pressure tracking (tiered) and periodic recovery snapshots.
"""
from __future__ import annotations

import json
from typing import Any

from mcp_server.scan_engine.budget import get_profile
from mcp_server.scan_engine.envelope._common import Envelope, _REPO_ROOT, _RECOVERY_SNAP_FILE


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
    import mcp_server.scan_engine.envelope as _env
    from core import session as scan_session
    scan_session.charge_context(len(json_str))
    profile = get_profile()
    pressure = scan_session.get_context_pressure(profile)

    _env._maybe_write_recovery_snapshot(scan_session)

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
