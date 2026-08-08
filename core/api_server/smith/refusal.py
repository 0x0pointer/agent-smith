"""
Usage-Policy refusal monitor — the recovery path for when Claude Code's
server-side content-safety classifier REFUSES a request mid-scan (e.g. "this
request ... appears to violate our Usage Policy" / "triggered cyber-related
safeguards").

That refusal never reaches the MCP server — no tool call is made — so the
envelope / smith-event layer is blind to it. Two failure shapes result:

  • headless ``claude -p``: the refusal ends the turn and the child exits. The
    watchdog respawns it, but the operator is told a GENERIC "Smith stopped"; the
    real cause (a policy refusal, fixable by switching model / skipping the step)
    is laundered away.
  • interactive ``claude``: the process stays ALIVE but wedged on the refused
    request — and because the watchdog is disabled for interactive runs
    (SMITH_WATCHDOG_DISABLED=1), NOTHING notices and the human is never told.

This monitor closes both gaps. It reads the driving Claude's transcript
(read-only), recognises the refusal as the terminal assistant turn, and then:

  A. NOTIFIES the operator with a distinct POLICY_REFUSAL alert.
  B. Enqueues a NON-BLOCKING skip steering directive that routes the agent AROUND
     the blocked step — record it as a coverage gap and continue — which the next
     turn consumes (a watchdog respawn in headless; the human typing "continue" in
     interactive). After repeated refusals on an interactive run it escalates to a
     blocking HIR so the human switches model.

It runs on its OWN always-on loop, independent of SMITH_WATCHDOG_DISABLED, because
the interactive case is exactly where detection matters most. It NEVER spawns a
process, so it cannot ghost-spawn during a human-driven scan and cannot change
Phase A/B behaviour. Fully fail-soft. Disable with SMITH_REFUSAL_MONITOR_DISABLED=1.
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib

import core.api_server as _api
import core.api_server.smith as _smith

from ._common import _log


def _int_env(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name, "") or "").strip() or default)
    except ValueError:
        return default


# Poll cadence (a wedge is not time-critical — the human just needs to be told).
_REFUSAL_POLL_SECONDS = _int_env("SMITH_REFUSAL_POLL_SECONDS", 45)
# Only consider transcripts touched recently — a wedged scan stops being written,
# so its mtime is roughly when it wedged; an old transcript is a past engagement.
_RECENT_WINDOW_SECONDS = _int_env("SMITH_REFUSAL_RECENT_WINDOW_SECONDS", 30 * 60)
# Distinct consecutive refusals before an interactive run escalates to a blocking HIR.
_REFUSAL_ESCALATE_AFTER = _int_env("SMITH_REFUSAL_ESCALATE_AFTER", 3)

# Substrings (lower-cased) that mark a Claude Code content-safety refusal. Kept broad
# enough to catch the known variants across models/clients without matching ordinary
# assistant prose.
_REFUSAL_MARKERS = (
    "appears to violate our usage policy",
    "cyber-related safeguards",
    "triggered cyber",
    "unable to respond to this request",
    "output blocked by content filtering policy",
)


def _looks_like_refusal(text: str) -> bool:
    """True when a piece of assistant text is a Claude Code Usage-Policy refusal."""
    t = (text or "").lower()
    return any(m in t for m in _REFUSAL_MARKERS)


# ── Transcript location + parsing (read-only) ────────────────────────────────

def _project_transcript_dir() -> pathlib.Path:
    """``~/.claude/projects/<slug>`` for this repo, where Claude Code writes the
    driving agent's transcript. The slug is the repo path with ``/`` and ``.``
    replaced by ``-`` (Claude Code's own convention)."""
    slug = str(_api._REPO_ROOT).replace("/", "-").replace(".", "-")
    return pathlib.Path.home() / ".claude" / "projects" / slug


def _read_tail_events(path: pathlib.Path, max_bytes: int = 300_000, max_events: int = 60) -> list:
    """Last few complete JSONL events from a transcript, reading only the tail so a
    multi-MB transcript stays cheap. Best-effort: returns [] on any read error."""
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()  # discard the partial first line after the seek
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events[-max_events:]


def _assistant_text_of(msg: dict) -> str:
    """Readable text of one assistant message. Falls back to the raw message JSON
    when it carries no text block (an API-error turn may be stored without one) so
    the marker scan still sees it."""
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        parts = [b.get("text", "") for b in content
                 if isinstance(b, dict) and b.get("type") == "text" and b.get("text")]
        if parts:
            return "\n".join(parts)
    try:
        return json.dumps(msg)
    except (TypeError, ValueError):
        return ""


def _terminal_assistant_text(events: list) -> str:
    """Text of the LAST assistant message in the tail (searching from the end), or
    ''. Searching from the end means a scan that RECOVERED — whose latest assistant
    turn is a normal tool call — correctly reads as not-wedged."""
    for e in reversed(events):
        msg = e.get("message") if isinstance(e, dict) else None
        if isinstance(msg, dict) and msg.get("role") == "assistant":
            return _assistant_text_of(msg)
    return ""


def _tail_has_pentest_tooluse(events: list) -> bool:
    """True when the tail contains a pentest-agent MCP tool call — the signal that
    this transcript is the SCAN driver, not an unrelated dev/chat conversation in
    the same repo. Used to avoid mis-identifying the operator's own Claude Code
    session as the wedged scan."""
    for e in events:
        msg = e.get("message") if isinstance(e, dict) else None
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            continue
        for b in content:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                name = str(b.get("name", ""))
                if "pentest-agent" in name or name.startswith("mcp__pentest"):
                    return True
    return False


def _evaluate_transcript(path: pathlib.Path, require_scan_relevance: bool):
    """Return ``(path, refusal_text, size)`` if this transcript is wedged on a
    refusal, else None. ``require_scan_relevance`` gates on a pentest-agent tool
    call (used for the heuristic interactive match; skipped when we KNOW the
    transcript is the scan's own recorded session)."""
    events = _read_tail_events(path)
    if not events:
        return None
    if require_scan_relevance and not _tail_has_pentest_tooluse(events):
        return None
    text = _terminal_assistant_text(events)
    if not _looks_like_refusal(text):
        return None
    try:
        return (path, text, path.stat().st_size)
    except OSError:
        return None


def _recorded_smith_sid() -> str | None:
    """The scan's own recorded claude session id (headless), or None. NEVER a
    directory scan — mirrors spawn._recorded_claude_session's safety rule."""
    try:
        from core import session as _s
        return _s.get_smith_session_id()
    except Exception:
        return None


def _find_wedged_transcript(now: float):
    """Locate the scan-driving transcript that is wedged on a refusal, or None.

    Two-tier: (1) if the scan recorded its OWN claude session id (headless spawn),
    trust that transcript directly; (2) otherwise (interactive — the human launched
    claude, so we minted no id) look at the NEWEST recently-touched scan transcript
    and report it wedged only if IT is the one on a refusal.

    The "newest wins" rule matters after recovery: once a fresh session resumes the
    scan, the abandoned transcript is still terminal-on-refusal on disk and inside
    the recent window, but it is NOT the current driver. Keying on the newest scan
    transcript means a recovered scan (newest activity is a healthy tool call) reads
    as not-wedged, instead of the monitor false-firing on the stale one until it
    ages out.
    """
    d = _project_transcript_dir()
    if not d.is_dir():
        return None
    sid = _recorded_smith_sid()
    if sid:
        p = d / f"{sid}.jsonl"
        if p.exists():
            return _evaluate_transcript(p, require_scan_relevance=False)
        # recorded id but no file yet — fall through to the heuristic
    newest = _newest_scan_transcript(d, now)
    if newest is None:
        return None
    p, events = newest
    text = _terminal_assistant_text(events)
    if not _looks_like_refusal(text):
        return None  # newest scan activity is healthy — recovered, not wedged
    try:
        return (p, text, p.stat().st_size)
    except OSError:
        return None


def _newest_scan_transcript(d: pathlib.Path, now: float):
    """The most recently modified in-window scan transcript (one that issues
    pentest-agent tool calls) as ``(path, events)``, or None. Isolating the scan
    keeps _find_wedged_transcript's newest-wins recovery rule readable."""
    newest = None  # (mtime, path, events)
    for p in d.glob("*.jsonl"):
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue
        if now - mtime > _RECENT_WINDOW_SECONDS:
            continue
        events = _read_tail_events(p)
        if not _tail_has_pentest_tooluse(events):
            continue  # not a scan transcript (e.g. an unrelated dev conversation)
        if newest is None or mtime > newest[0]:
            newest = (mtime, p, events)
    return (newest[1], newest[2]) if newest else None


# ── Mode + context helpers ───────────────────────────────────────────────────

def _watchdog_enabled() -> bool:
    """True in headless mode (watchdog running), False in interactive mode
    (SMITH_WATCHDOG_DISABLED set — the operator drives claude in a terminal)."""
    return os.environ.get("SMITH_WATCHDOG_DISABLED", "").strip().lower() not in ("1", "true", "yes")


def _active_skill(session_data: dict) -> str:
    """Best-effort name of the skill the scan was running when it wedged."""
    s = session_data.get("skill")
    if isinstance(s, str) and s and s != "unknown":
        return s
    hist = session_data.get("skill_history") or []
    if hist and isinstance(hist[-1], dict):
        return str(hist[-1].get("skill", "") or "")
    return ""


# ── Recovery + notification ──────────────────────────────────────────────────

def _skip_directive_message(skill: str) -> str:
    """The recovery instruction queued after a refusal. It routes the agent AROUND
    the blocked step — skip, record the gap, continue — and explicitly forbids
    rewording the request to evade the filter."""
    where = f" while running the '{skill}' skill" if skill else ""
    return (
        "CONTENT-SAFETY REFUSAL RECOVERY: Claude Code's Usage-Policy filter refused your "
        f"previous request{where} (flagged as violative / a cyber safeguard). Do NOT retry that "
        "exact request or payload — it will only be refused again. Instead: "
        "(1) if the blocked step maps to a coverage cell, close that cell as `skipped` with note "
        "'content-filter refusal'; "
        "(2) call report(action='note') recording which step was blocked, for the audit trail; "
        "(3) CONTINUE with the remaining pending coverage — do not stop the scan. "
        "If an entire skill sub-step is blocked (e.g. generating a reverse-shell payload), note it "
        "as a documented gap and move to the next applicable technique. Do NOT try to reword the "
        "request to get around the filter."
    )


def _enqueue_skip_directive(skill: str) -> None:
    try:
        from core.steering import steering_queue
        steering_queue.add_directive(
            code="POLICY_REFUSAL_SKIP",
            message=_skip_directive_message(skill),
            priority="high",
            skill=skill or None,
            trigger="usage_policy_refusal",
            force=True,  # a recovery instruction must never be deduped away
        )
    except Exception:
        _log.exception("refusal monitor: failed to enqueue skip directive")


def _notify_refusal(skill: str, interactive: bool) -> None:
    where = f" in skill '{skill}'" if skill else ""
    if interactive:
        body = (
            f"Claude Code refused a request (content-safety / cyber safeguard){where}. Your "
            "interactive scan is stalled on it and will NOT retry on its own. A skip-past-this "
            "instruction is already queued — type 'continue' in your terminal (it records the "
            "blocked step as a gap and moves on), or click 'Restart Smith' on the dashboard. If "
            "refusals keep happening, restart with SMITH_SPAWN_MODEL=claude-sonnet-5."
        )
    else:
        body = (
            f"Claude Code refused a request (content-safety / cyber safeguard){where}. A "
            "skip-past-this instruction has been queued; the watchdog will respawn and route "
            "around the blocked step. If refusals persist for this model, set "
            "SMITH_SPAWN_MODEL=<another model> so respawns are less refusal-prone."
        )
    _smith._watchdog_notify("Claude Code refused a request (Usage Policy)", body, "POLICY_REFUSAL")


def _escalate_refusal_hir(skill: str) -> None:
    """After repeated refusals on an INTERACTIVE run, pause for a human decision.
    Only fired interactive (watchdog off) so it never blocks the watchdog's own
    auto-recovery; headless leans on the watchdog's existing per-scan / no-progress
    caps instead."""
    try:
        from core.session.intervention import trigger_intervention, get_intervention
        if get_intervention():
            return  # already paused — don't stack interventions
        where = f" in skill '{skill}'" if skill else ""
        trigger_intervention(
            code="HIR_POLICY_REFUSAL",
            situation=(f"Claude Code has refused {_smith._refusal_consecutive} requests in a row"
                       f"{where} (content-safety / cyber safeguard). Skipping past isn't clearing it."),
            tried=["Queued a skip-past-this steering directive after each refusal"],
            options=["Skip the blocked step and continue",
                     "Switch model (restart with SMITH_SPAWN_MODEL=claude-sonnet-5)",
                     "Abort the scan"],
        )
    except Exception:
        _log.exception("refusal monitor: HIR escalation failed")


def _handle_refusal(session_data: dict, refusal_text: str) -> None:
    """A refusal has been (newly) detected: queue the skip directive, notify the
    operator, log it, and — interactive only, after repeated refusals — escalate."""
    skill = _active_skill(session_data)
    interactive = not _watchdog_enabled()
    _enqueue_skip_directive(skill)
    _notify_refusal(skill, interactive)
    _log.warning(
        "refusal monitor: POLICY_REFUSAL detected (%s, skill=%s, consecutive=%d) — queued skip "
        "directive + notified operator: %.140s",
        "interactive" if interactive else "headless", skill or "?",
        _smith._refusal_consecutive, refusal_text.replace("\n", " "),
    )
    if interactive and _smith._refusal_consecutive >= _REFUSAL_ESCALATE_AFTER:
        _escalate_refusal_hir(skill)


# ── Loop ─────────────────────────────────────────────────────────────────────

async def _refusal_monitor_tick(now: float) -> None:
    """One monitor pass. Idle unless a scan is running; detects a NEW refusal
    (dedup by transcript size so a persistent wedge alerts once) and hands off to
    _handle_refusal. Resets the consecutive-refusal streak whenever the scan is no
    longer wedged (recovered)."""
    session_data = _api._read_json(_api._SESSION_FILE) or {}
    if session_data.get("status") != "running":
        _smith._refusal_consecutive = 0
        return
    loop = asyncio.get_running_loop()
    hit = await loop.run_in_executor(None, _find_wedged_transcript, now)
    if not hit:
        _smith._refusal_consecutive = 0  # healthy / recovered — clear the streak
        return
    path, refusal_text, size = hit
    if _smith._refusal_last_alert.get(path.name) == size:
        return  # already handled this exact wedge (unchanged transcript)
    _smith._refusal_last_alert[path.name] = size
    _smith._refusal_consecutive += 1
    _handle_refusal(session_data, refusal_text)


async def _refusal_monitor_loop() -> None:
    """Background task: watch the driving Claude's transcript for Usage-Policy
    refusals and drive notify + skip-recovery. Always on (independent of the
    watchdog) so the interactive case is covered; fail-soft forever."""
    import time as _time
    while True:
        try:
            await asyncio.sleep(_REFUSAL_POLL_SECONDS)
            await _refusal_monitor_tick(_time.time())
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("refusal monitor loop error (continuing)")
