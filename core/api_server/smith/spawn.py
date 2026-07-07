"""
Spawn logic shared by the /api/restart-smith endpoint and the watchdog.

Builds the recovery/resume prompt, resolves a resumable opencode session, and
launches the client detached. Sibling helpers (prompts, source-tag, session
lookup) and the no-progress counter/cold-start threshold are reached through the
package object (``_smith.<name>``) so patches on the facade are honoured; paths
and the session-list helper stay on the parent (``_api.<name>``).
"""
from __future__ import annotations

import asyncio

import core.api_server as _api
import core.api_server.smith as _smith

from ._common import _log, _SPAWN_SOURCE_TAGS

# A healthy `claude -p` / `opencode run` agent runs for minutes. A child that
# exits within this window died on startup (bad/empty auth, missing binary,
# "Credit balance is too low") and must NOT be booked as a successful respawn.
_SPAWN_LIVENESS_SECONDS = 8


def _spawn_source_tag(source: str) -> str:
    """Map a _spawn_smith() source argument to its audit-log tag."""
    return _SPAWN_SOURCE_TAGS.get(source, f"spawn_{source}")


def _latest_opencode_session(directory: str) -> str | None:
    """Newest opencode session whose directory matches `directory` — i.e. the
    scan's own session, so a watchdog respawn can ``--session <id>`` resume it
    (keeping the agent's in-context memory of what it already tested and which
    tools fail here) instead of cold-starting from the recovery brief and
    re-walking the same dead ends.

    Read-only and best-effort: shells out to opencode's own ``session list``
    rather than coupling to its SQLite schema, and returns None on ANY problem
    so the caller cleanly falls back to a cold start (first launch, opencode
    missing, mismatched dir, parse error, timeout).
    """
    import json
    import os
    import shutil
    import subprocess
    try:
        binary = shutil.which("opencode")
        if not binary:
            return None
        target = os.path.realpath(directory)
        out = subprocess.run(
            [binary, "session", "list", "--format", "json", "-n", "20"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None
        sessions = json.loads(out.stdout)
        if not isinstance(sessions, list):
            return None
        for s in sessions:  # session list returns newest-first
            d = s.get("directory")
            if d and s.get("id") and os.path.realpath(d) == target:
                return s["id"]
        return None
    except Exception:
        return None


def _recorded_claude_session() -> str | None:
    """The scan's OWN recorded claude session id, or None if none recorded yet.

    Set by _spawn_smith when it cold-starts a claude child with an explicit
    ``--session-id`` (persisted in session.json), so a later respawn resumes EXACTLY that
    session. This deliberately does NOT scan ``~/.claude/projects`` for the "largest"
    transcript: in a dev/repo working directory the largest session is often the operator's
    own interactive Claude Code conversation, and resuming THAT headless under
    --dangerously-skip-permissions with a pentest prompt is unsafe. We only ever resume a
    session we explicitly minted for this scan."""
    try:
        from core import session as _s
        return _s.get_smith_session_id()
    except Exception:
        return None


def _spawn_model() -> str | None:
    """Optional model override for a respawned child (env ``SMITH_SPAWN_MODEL``).

    Unset by default so the child inherits the operator's own model choice. Set it
    (e.g. ``SMITH_SPAWN_MODEL=claude-sonnet-4-5``) as the hard lever when Usage-Policy
    refusals persist for a given model on cold offensive-security prompts — the refusal
    message itself suggests switching models."""
    import os
    return (os.environ.get("SMITH_SPAWN_MODEL", "") or "").strip() or None


# Truthful authorized-engagement framing prepended to every respawn prompt. A
# detached `claude -p` respawn issues a FRESH request; without the context that this
# is a sanctioned, operator-initiated assessment, the bare "recover the pentest and
# start tool calls" instruction can trip Anthropic's Usage-Policy classifier — the
# child then exits with a "violative cyber content" refusal before running a single
# tool (seen in the wild as a respawn loop that never tests). Stating the real
# engagement context lets the model correctly recognise authorized defensive work.
_AUTHORIZED_ENGAGEMENT_PREAMBLE = (
    "You are a professional penetration tester continuing an AUTHORIZED, "
    "operator-initiated security assessment that is already in progress. The target "
    "is owned by the operator and is explicitly in scope for this sanctioned "
    "engagement, orchestrated through the agent-smith testing harness. This is "
    "legitimate defensive security work: the goal is to find, prove, and document "
    "vulnerabilities so the operator can remediate them. Proceed with the engagement.\n\n"
)


def _cold_recovery_prompt(directive_text: str) -> str:
    """Prompt for a COLD spawn (no resumable session): the agent has no prior
    context, so it must reconstruct its position from session(action='recovery').
    Prefixed with the authorized-engagement framing so a cold `claude -p` request
    isn't refused by the Usage-Policy classifier before it runs any tool."""
    return (
        _AUTHORIZED_ENGAGEMENT_PREAMBLE +
        "Recover the active pentest scan. "
        "Call session(action='recovery') to get your current position, "
        "then immediately execute the EXECUTE_NOW field — do NOT ask for confirmation, "
        "do NOT summarise what you plan to do, just start tool calls. "
        "If session(action='status') returns qa_alerts, answer them with "
        "session(action='qa_reply') before continuing. "
        "Keep working autonomously until you are genuinely blocked and cannot "
        "proceed without new human input. Do NOT stop to ask questions."
        + directive_text
    )


def _resume_prompt(directive_text: str) -> str:
    """Prompt for a RESUMED spawn (--session <id>): the agent's full prior
    conversation is rehydrated, so it must NOT re-run recovery from scratch —
    just continue, and explicitly break out of any failing-tool loop it was
    stuck in (the wedge that cold recovery kept resurrecting)."""
    return (
        _AUTHORIZED_ENGAGEMENT_PREAMBLE +
        "You are resuming your OWN pentest session after an automatic restart — your full "
        "prior context is intact. Do NOT call session(action='recovery') or re-read everything "
        "from scratch; pick up exactly where you left off and continue testing the next pending "
        "coverage cells. If you were stuck repeating a tool that kept FAILING, STOP using it and "
        "switch approaches (e.g. use kali with curl instead of http_request). You may call "
        "session(action='status') once to re-sync coverage and answer any qa_alerts with "
        "session(action='qa_reply'). Keep working autonomously until you are genuinely blocked. "
        "Do NOT stop to ask questions, do NOT summarise — just resume tool calls."
        + directive_text
    )


def _clear_qa_alerts() -> None:
    """Clear QA alerts so Smith's first post-respawn tool call doesn't immediately
    re-trigger the same HIR that caused the intervention. The QA daemon re-evaluates
    every 120s and re-fires any persistent issue on the next cycle."""
    try:
        from core import paths as _paths, store as _store
        import json as _json
        _qa_file = _paths.QA_STATE_FILE
        if _qa_file.exists():
            _qa = _json.loads(_qa_file.read_text())
            _qa["alerts"] = []
            _store.save(_qa_file, _qa, indent=None)
    except Exception as _e:
        _log.debug("spawn_smith: qa_state clear failed: %s", _e)


async def _resolve_resume_sid(client: str, loop) -> str | None:
    """Resolve the client's own session id to resume, or None for a cold start.

    opencode resolves via ``opencode session list``; claude returns the session id we
    RECORDED for this scan (minted with ``--session-id`` on a prior cold start), NEVER a
    directory scan — so a respawn can only resume the scan's own session, not the
    operator's unrelated interactive Claude Code conversation. Resuming keeps the agent's
    in-context memory AND, for claude, presents the model a continuation of visibly
    authorized work rather than a fresh cold offensive-security request.

    Cold-starts (returns None) when recent respawns have made NO progress — a wedged
    session keeps re-hitting the same hang/refusal on resume, so the caller mints a fresh
    session instead. Breaks the loop one rung before HIR_NO_PROGRESS, and applies to the
    manual "Restart Smith" button too so a manual restart on a wedged scan finally helps.
    """
    if client == "opencode":
        resolver = lambda: _api._latest_opencode_session(str(_api._REPO_ROOT))
    elif client == "claude":
        resolver = lambda: _api._recorded_claude_session()
    else:
        return None
    resume_sid = await loop.run_in_executor(None, resolver)
    if resume_sid and _smith._watchdog_no_progress_count >= _smith._WATCHDOG_COLD_START_AFTER:
        _log.warning(
            "watchdog: %d no-progress respawn(s) — COLD-STARTING a fresh session "
            "instead of resuming the wedged one (agent recovers from disk)",
            _smith._watchdog_no_progress_count,
        )
        return None
    return resume_sid


async def _resolve_session_plan(client: str, directive_text: str, loop):
    """Decide how this respawn attaches to a session and which prompt it uses.

    Either resume the scan's OWN recorded session, or cold-start — minting a fresh claude
    ``--session-id`` so the NEXT respawn can resume exactly it (never a directory-scanned
    one). Returns ``(resume_sid, assign_session_id, prompt, audit_kind)``."""
    resume_sid = await _resolve_resume_sid(client, loop)
    assign_session_id = None
    if client == "claude" and not resume_sid:
        import uuid as _uuid
        assign_session_id = str(_uuid.uuid4())
    if resume_sid:
        prompt = _smith._resume_prompt(directive_text)
        audit_kind = f"resume session={resume_sid}"
    else:
        prompt = _smith._cold_recovery_prompt(directive_text)
        audit_kind = f"cold-start session={assign_session_id}" if assign_session_id else "cold-start"
    return resume_sid, assign_session_id, prompt, audit_kind


def _build_spawn_args(binary: str, client: str, resume_sid: str | None, prompt: str,
                      assign_session_id: str | None = None) -> list[str]:
    """Assemble argv for the client subprocess.

    claude and opencode-cold both pass --dangerously-skip-permissions: a detached
    background spawn has no controlling TTY, so an interactive permission prompt would
    hang on closed stdin or exit. opencode auto-approves prompts not explicitly denied in
    opencode.json's permission.deny block (the installer recommends a starter set of
    destructive-command denials).

    A resume rehydrates the scan's prior conversation linearly (not a fork): ``--resume
    <id>`` for claude, ``--session <id>`` for opencode. On a COLD claude start we instead
    MINT the session with ``--session-id <assign_session_id>`` so the next respawn can
    resume exactly it — we never directory-scan for a session to resume. An optional
    ``SMITH_SPAWN_MODEL`` adds ``--model`` for claude.
    """
    model = _spawn_model()
    if client == "claude":
        args = [binary, "--dangerously-skip-permissions"]
        if model:
            args += ["--model", model]
        if resume_sid:
            # Resume the scan's OWN recorded session (kept context, visibly authorized).
            args += ["--resume", resume_sid]
        elif assign_session_id:
            # Cold start: mint an explicit id so the NEXT respawn resumes exactly this
            # session — not whatever transcript happens to be largest on disk.
            args += ["--session-id", assign_session_id]
        args += ["-p", prompt]
        return args
    if resume_sid:
        return [binary, "run", "--session", resume_sid, "--dangerously-skip-permissions", prompt]
    return [binary, "run", "--dangerously-skip-permissions", prompt]


def _spawn_child_env(client: str) -> dict:
    """Environment for the respawned client — matching the AUTH CONTEXT the operator's
    interactive run used.

    The dashboard/MCP-server process loads the repo ``.env`` (mcp_server._app._load_dotenv),
    which commonly sets ``ANTHROPIC_API_KEY`` for server-side LLM features (QA agent,
    adjudication). But a detached ``claude -p`` that inherits that key bills against the
    API pay-as-you-go account instead of the operator's Claude subscription — and when
    that API account is empty the child dies instantly with "Credit balance is too low"
    (the exact HIR_NO_PROGRESS dead end seen in the wild). The operator's interactive TUI
    ran on their subscription precisely because their shell had no such key. So for a
    ``claude`` respawn we drop the API-key vars, letting the headless child fall back to
    the same logged-in subscription. Opt back into API-key billing with
    ``SMITH_SPAWN_USE_API_KEY=1`` (e.g. a subscription-less CI box).
    """
    import os as _os
    env = _os.environ.copy()
    _use_api_key = _os.environ.get("SMITH_SPAWN_USE_API_KEY", "").lower() in ("1", "true", "yes")
    if client == "claude" and not _use_api_key:
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("ANTHROPIC_AUTH_TOKEN", None)
    return env


def _tail_spawn_log(log_path, max_chars: int = 240) -> str:
    """Last non-empty line of the spawn log — carries the child's own exit reason
    (e.g. 'Credit balance is too low') so a startup failure is diagnosable."""
    try:
        lines = [ln.strip() for ln in log_path.read_text(errors="replace").splitlines() if ln.strip()]
        for ln in reversed(lines):
            if ln.startswith("=== ["):  # skip our own audit banner
                continue
            return ln[:max_chars]
    except Exception:
        pass
    return ""


def _build_spawn_kwargs(log_fh, client: str) -> dict:
    """Build create_subprocess_exec kwargs, detaching the child so signals to the
    dashboard process don't reach it. POSIX uses os.setsid() via start_new_session;
    Windows uses the CREATE_NEW_PROCESS_GROUP creationflag — same intent, different API.
    ``env`` is set explicitly so the child's billing/auth matches the operator's run
    (see _spawn_child_env)."""
    spawn_kwargs: dict = {
        "stdout": log_fh, "stderr": log_fh, "cwd": str(_api._REPO_ROOT),
        "env": _spawn_child_env(client),
    }
    import sys as _sys
    if _sys.platform == "win32":
        # CREATE_NEW_PROCESS_GROUP is only defined on Windows CPython; the literal
        # 0x00000200 is the documented Win32 flag, used as a fallback so cross-platform
        # tests that force sys.platform="win32" still resolve to the expected integer.
        import subprocess as _subprocess
        spawn_kwargs["creationflags"] = getattr(_subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    else:
        spawn_kwargs["start_new_session"] = True
    return spawn_kwargs


async def _spawn_smith(client: str, source: str = "api") -> tuple[bool, int | str]:
    """Core spawn logic shared by the /api/restart-smith endpoint and the
    watchdog. Returns (ok, pid_or_error_message). source is logged so the
    audit trail distinguishes manual restarts from auto-restarts.

    For opencode, a respawn RESUMES the scan's own session (``--session <id>``)
    when one is found, so the agent keeps its memory instead of cold-starting;
    it falls back to a cold ``run`` + full recovery prompt otherwise.
    """
    try:
        from core.steering import steering_queue
        active = steering_queue.get_active()
        directive_text = ""
        if active:
            directive_text = "\n\nAct on these pending human instructions immediately after recovery:\n" + \
                "\n".join(f"- {d.message}" for d in active)

        from core import session as scan_session
        scan_session.load_from_disk(force=True)
        current = scan_session.get() or {}
        _terminal = {"complete", "incomplete_with_unresolved_blockers", "limit_reached"}
        if current.get("status") in _terminal:
            return (
                False,
                f"Cannot restart: scan is already in terminal state '{current.get('status')}'. Start a new scan instead.",
            )
        if current.get("status") == "intervention_required":
            scan_session.resolve_intervention(
                "CONTINUE",
                f"Smith restarted (source={source})",
            )
        _clear_qa_alerts()

        log_path = _api._REPO_ROOT / "logs" / "smith_restart.log"
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: log_path.parent.mkdir(parents=True, exist_ok=True))

        # Attach to the scan's own session (opencode: --session; claude: our recorded
        # --session-id), or cold-start — minting a fresh claude session id so the next
        # respawn resumes exactly it. Recorded once the child proves live, below.
        resume_sid, assign_session_id, prompt, audit_kind = await _resolve_session_plan(
            client, directive_text, loop
        )
        audit_line = f"\n=== [{source}] spawning {client} ({audit_kind}) at {loop.time()} ===\n"
        await loop.run_in_executor(None, lambda: log_path.open("a").write(audit_line))

        import shutil
        binary = shutil.which(client)
        if not binary:
            return False, f"{client} binary not found on PATH"
        args = _build_spawn_args(binary, client, resume_sid, prompt, assign_session_id)

        log_fh = await loop.run_in_executor(None, lambda: log_path.open("a"))
        spawn_kwargs = _build_spawn_kwargs(log_fh, client)

        proc = await asyncio.create_subprocess_exec(*args, **spawn_kwargs)

        # Liveness probe: a healthy agent runs for minutes, so proc.wait() times out
        # (good). A child that exits within the window died on startup — most often
        # "Credit balance is too low" (API-key billing on an empty account). Do NOT
        # book that as a successful respawn: return the child's own last log line so
        # the watchdog surfaces the REAL cause instead of laundering it into a generic
        # HIR_NO_PROGRESS coverage dead-end.
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=_SPAWN_LIVENESS_SECONDS)
        except asyncio.TimeoutError:
            rc = None  # still alive after the probe → healthy
        except Exception as _probe_err:
            # Never fail a real spawn because the liveness probe itself errored
            # (e.g. a non-awaitable proc stub) — assume alive and proceed.
            _log.debug("spawn_smith: liveness probe error, assuming alive: %s", _probe_err)
            rc = None
        if rc is not None:
            reason = await loop.run_in_executor(None, lambda: _tail_spawn_log(log_path))
            _log.warning(
                "spawn_smith: %s exited rc=%s within %ss of launch — not a live respawn: %s",
                client, rc, _SPAWN_LIVENESS_SECONDS, reason or "(no output)",
            )
            return False, f"{client} exited on launch (rc={rc}): {reason or 'no output'}"

        _api._SMITH_PID_FILE.write_text(str(proc.pid))
        _api._SMITH_CLIENT_FILE.write_text(client)

        # Scan-lock the chosen client into session.json so subsequent
        # watchdog restarts can't drift to a different CLI. This is the
        # other half of the fix: _detect_active_client() reads
        # smith_proc.client first, and _spawn_smith() guarantees it's
        # always populated after a successful spawn. Source distinguishes
        # dashboard restarts from auto-restarts so a later audit is clear.
        try:
            from core import session as scan_session
            scan_session.set_smith_proc(
                pid=proc.pid,
                client=client,
                source=_smith._spawn_source_tag(source),
            )
            # Persist the minted claude session id so the NEXT respawn resumes THIS
            # session (safe, scan-owned) rather than directory-scanning for one.
            if assign_session_id:
                scan_session.set_smith_session_id(assign_session_id)
        except Exception as e:
            # Never break the spawn path on a session-update failure —
            # the file-based smith.client write above is the operational
            # backup. Just note it for diagnostics.
            _log.debug("spawn_smith: scan-lock write failed: %s", e)

        return True, proc.pid
    except Exception:
        _log.exception("spawn_smith failed")
        return False, "spawn failed"
