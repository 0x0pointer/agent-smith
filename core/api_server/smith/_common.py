"""
Shared imports, logger, and tuning constants for the smith package.

Split out for the <300-lines-per-file convention. Names here are re-exported by
the package facade (__init__). Submodule functions reach cross-cutting siblings
and the mutable watchdog counters through the package object at call time
(``import core.api_server.smith as _smith`` → ``_smith.<name>``) so that
unittest.mock.patch on ``core.api_server.smith.<name>`` (and the parent
``core.api_server`` re-export) is observed identically to the old single module.
"""
from __future__ import annotations

import logging

# Logger name pinned to the historical single-module name so log records are
# identical after the split (submodule __name__ would drift them otherwise).
_log = logging.getLogger("core.api_server.smith")

# No scan activity for this long → Smith is considered stopped/hung.
# History: 60s → 300s (Qwen3.6-A3B thinking-mode runs 2–3 min between tool
# calls) → 1800s. On a large/near-full context window a single turn (slow
# prefill + compaction on the local model) can exceed 5 min with no tool call,
# so 300s false-killed a healthy-but-slow Smith and triggered a kill→respawn
# death spiral (the watchdog killed every respawn before it could call a tool).
# 30 min tolerates the slowest realistic turn while still catching real deaths.
_SMITH_IDLE_SECONDS = 1800

# Fast "loop exited mid-scan" stall threshold. The 30-min idle window above is a
# blunt timer that can't tell a slow generation from a finished agent loop, so a
# Smith whose loop EXITED (model ended its turn with no tool call) sits idle for
# up to 30 min before respawn. _smith_stalled_pid() catches that in minutes by
# also checking the process is NOT generating (no live connection to the model
# endpoint) and the scan still has pending cells — so we never false-kill a slow
# generation, only a genuinely-exited loop.
_SMITH_STALL_SECONDS = 300

# No-progress backoff: a respawn that produces no new finding, no newly-closed
# cell, and no fresh MCP activity is futile — it just re-enters the same dead end
# (recovery → list → exit). After this many consecutive futile respawns the
# watchdog pauses for a human (HIR_NO_PROGRESS) instead of looping the model.
_WATCHDOG_MAX_NO_PROGRESS = 3
# Cold-start fallback: after this many no-progress respawns, stop RESUMING the
# opencode session and cold-start a fresh one instead. A long scan's session
# bloats until the model hangs just re-loading it on resume (resume → hang → kill
# → resume … the observed loop), so a resume can never recover it. A cold start
# gives the model a small, clean context and it recovers its position from disk
# (session(action='recovery')). Set one rung below MAX_NO_PROGRESS so the fresh
# context gets a real shot before the run escalates to HIR_NO_PROGRESS.
_WATCHDOG_COLD_START_AFTER = 2

# Cumulative per-scan auto-respawn cap. _WATCHDOG_MAX_PER_HOUR is a ROLLING window,
# so a thorough scan — which is operator-terminated and never auto-completes (status
# stays "running" indefinitely) — lets the watchdog respawn ~20/hour forever: the
# observed "40 agents overnight" runaway. This is a HARD cap on TOTAL auto-respawns
# for a single scan (keyed on the session id). Once hit, the watchdog stops respawning
# and escalates to the operator instead of silently looping. Genuine crash-resume still
# works up to this many times per scan; a runaway can't exceed it.
_WATCHDOG_MAX_PER_SCAN = 8

_KNOWN_CLIENTS = ("claude", "opencode", "codex")

# Small lookup table for the audit-log tag that goes into session.json's
# smith_proc.source field. Replaces the chained ternary that SonarQube
# flagged as a confusing nested conditional (python:S3358). Adding a new
# spawn source = one entry here.
_SPAWN_SOURCE_TAGS = {
    "watchdog": "watchdog_spawn",
    "api":      "dashboard_spawn",
}

# Throttle so a daemon that refuses to come up doesn't get hammered every tick.
_MCP_SSE_RESTART_MIN_GAP_SECONDS = 30

# Canonical launchd label for the MCP SSE daemon — matches the plist
# (installers/com.agent-smith.mcp-sse.plist) and install-launchd.sh.
_MCP_LAUNCHD_LABEL = "com.agent-smith.mcp-sse"

# Process liveness needles used by _smith_running()'s last-resort psutil check
# live in core.client_patterns (looks_like_smith) — the single place a new
# client's cmdline signature is added.
