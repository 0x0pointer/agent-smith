"""Single source of truth for recognizing Smith's driving clients by cmdline.

Two *different* questions are answered from the same underlying knowledge of how
each client (claude / opencode / codex) appears in a process command line. They
are intentionally kept as separate functions because they want different
strictness — do NOT collapse them into one matcher:

  * :func:`classify_client` — "WHICH client is this PID?" Used by
    ``core.session.process_detect`` to label an MCP connection. Broad on
    purpose so any real invocation shape resolves.

  * :func:`looks_like_smith` / :data:`SMITH_PROC_NEEDLES` — "is ANY Smith-driving
    process alive?" Used by ``core.api_server.smith`` as a last-resort liveness
    fallback. Anchored tighter (e.g. requires the ``--dangerously-skip-permissions``
    flag, not a bare ``claude``) so unrelated processes don't false-positive a
    running scan.

Add a new client in ONE place: extend the matchers below and, if it should also
count toward liveness, add its anchored needle(s) to ``SMITH_PROC_NEEDLES``.
"""
from __future__ import annotations


# ── "which client?" matchers (broad) ───────────────────────────────────────────
def _match_claude(cmd: str) -> bool:
    # dashboard-spawned uses --dangerously-skip-permissions; the older `-p`
    # shorthand exists for completeness. Bare `claude` TUI is out of scope here.
    return "claude" in cmd and ("dangerously-skip-permissions" in cmd or " -p " in cmd)


def _match_opencode(cmd: str) -> bool:
    # opencode is commonly `node /Users/<u>/.opencode/bin/opencode run …` or
    # `node …/opencode/dist/index.js`. Catch both, the direct binary, the
    # dashboard's literal `opencode run …`, the raw TUI, and any /opencode/ path
    # component (npm dist path).
    return (".opencode/bin/opencode" in cmd
            or "/opencode/dist" in cmd
            or "opencode run" in cmd
            or "/opencode" in cmd
            or cmd.startswith("opencode"))


def _match_codex(cmd: str) -> bool:
    return "codex" in cmd and ("run" in cmd or "mcp" in cmd)


# Order matters only if two matchers could both fire; in practice they're
# mutually exclusive on real cmdlines.
_MATCHERS: tuple[tuple[str, "callable"], ...] = (
    ("claude", _match_claude),
    ("opencode", _match_opencode),
    ("codex", _match_codex),
)


def classify_client(cmd: str) -> str | None:
    """Return the Smith client name for a command line, or ``None``.

    Case-insensitive; callers may pass raw or lowercased cmdlines.
    """
    lowered = cmd.lower()
    for name, matcher in _MATCHERS:
        if matcher(lowered):
            return name
    return None


# ── "is Smith alive?" needles (strict, anchored) ────────────────────────────────
# Substrings a psutil-based fallback treats as "a Smith scan is running". Anchored
# to project-specific binaries + flags so unrelated processes don't false-positive.
SMITH_PROC_NEEDLES: tuple[str, ...] = (
    # claude CLI driving an agent-smith scan
    "claude --dangerously-skip-permissions",
    # opencode run (direct binary OR wrapped via node)
    ".opencode/bin/opencode",
    "opencode run",
    # codex MCP-server launches
    "codex run",
    "codex mcp",
)


def looks_like_smith(cmd: str) -> bool:
    """True if a command line matches a Smith liveness needle (strict)."""
    lowered = cmd.lower()
    return any(needle in lowered for needle in SMITH_PROC_NEEDLES)
