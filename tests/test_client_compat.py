"""Track 4: cross-client contract smoke tests.

agent-smith must run identically on Claude Code, opencode, and Codex. The
client-facing contract is enforced only by documentation the model reads
(CLAUDE.md) — nothing else guarantees the tool set, the tool-name translation,
or that the documented skills actually exist. These tests lock that contract so
it can't drift silently.
"""
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_CLAUDE_MD = _REPO / "CLAUDE.md"
_SKILLS_DIR = _REPO / "skills"

# The five consolidated MCP tools. Adding/removing one is a client-facing change
# that must be reflected in CLAUDE.md — these tests make that coupling explicit.
EXPECTED_TOOLS = {"scan", "kali", "http", "report", "session"}


def _registered_tools() -> tuple[str, set[str]]:
    """Enumerate the server's registered tools in a FRESH interpreter.

    Registration is decorator-driven at import; running it in a subprocess
    mirrors real server startup and avoids the shared-`mcp`-singleton state that
    the suite's global-isolation fixtures otherwise perturb.
    """
    code = (
        "import mcp_server.scan_tools, mcp_server.kali_tools, mcp_server.http_tools, "
        "mcp_server.report_tools, mcp_server.session_tools;"
        "from mcp_server._app import mcp;"
        "print(mcp.name);"
        "print(','.join(sorted(mcp._tool_manager._tools.keys())))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=str(_REPO),
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, f"server import failed:\n{out.stderr[-2000:]}"
    lines = [ln for ln in out.stdout.strip().splitlines() if ln]
    name, tools_csv = lines[-2], lines[-1]
    return name, set(filter(None, tools_csv.split(",")))


def test_mcp_registers_exactly_the_five_tools():
    name, tools = _registered_tools()
    assert name == "pentest-agent"
    assert tools == EXPECTED_TOOLS


def _tool_names() -> set[str]:
    return _registered_tools()[1]


def test_claude_md_documents_every_registered_tool():
    """Doc-accuracy: the shorthand the model is told to call must match what the
    server actually registers. A tool added without a CLAUDE.md entry (or vice
    versa) fails here."""
    doc = _CLAUDE_MD.read_text()
    for tool in _tool_names():
        assert f"`{tool}(" in doc or f"{tool}(action" in doc, (
            f"MCP tool '{tool}' is registered but not documented in CLAUDE.md"
        )


def test_claude_md_documents_both_client_naming_schemes():
    """The tool-name translation the model relies on (bare shorthand fails on
    opencode/Codex) must stay documented for every client."""
    doc = _CLAUDE_MD.read_text()
    # Claude Code auto-resolves the mcp__pentest-agent__ prefix...
    assert "mcp__pentest-agent__" in doc
    # ...opencode / Codex need the pentest-agent_ form.
    assert "pentest-agent_" in doc
    assert "opencode" in doc and "Codex" in doc


# Core skills CLAUDE.md tells the agent it can chain into. Each must resolve to a
# real SKILL.md so a scan doesn't chain into a missing skill on any client.
CORE_SKILLS = {
    "web-exploit", "api-security", "codebase", "post-exploit", "credential-audit",
    "ai-redteam", "cloud-security", "container-k8s-security", "ad-assessment",
    "network-assess", "osint", "ssl-tls-audit", "metasploit", "reverse-shell",
    "ios-security", "android-security",
}


def _skill_leaves() -> set[str]:
    return {p.parent.name for p in _SKILLS_DIR.rglob("SKILL.md")}


def _skills_populated() -> bool:
    """True only when the submodule is actually checked out AND populated. A fresh
    clone (or a checkout without --recursive, or mid `git submodule update`) leaves
    `skills/` as an empty gitlink dir that EXISTS but has no SKILL.md — those
    environment states must SKIP, not hard-fail the suite."""
    return _SKILLS_DIR.exists() and any(_SKILLS_DIR.rglob("SKILL.md"))


@pytest.mark.skipif(not _skills_populated(), reason="skills submodule not checked out/populated")
def test_core_skills_present_in_submodule():
    leaves = _skill_leaves()
    missing = CORE_SKILLS - leaves
    assert not missing, f"CLAUDE.md references skills with no SKILL.md: {sorted(missing)}"


@pytest.mark.skipif(not _skills_populated(), reason="skills submodule not checked out/populated")
def test_skill_leaf_names_are_unique():
    """Skills install to a flat per-client dir (~/.claude/skills/<leaf>/), so two
    skills sharing a leaf name would clobber each other on install."""
    leaves = [p.parent.name for p in _SKILLS_DIR.rglob("SKILL.md")]
    dupes = {n for n in leaves if leaves.count(n) > 1}
    assert not dupes, f"duplicate skill leaf names would collide on install: {sorted(dupes)}"
