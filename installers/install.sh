#!/usr/bin/env bash
# install.sh — set up pentest-agent for the current user
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "${RED}✗${NC} $*"; exit 1; }

echo ""
echo "  pentest-agent installer"
echo "  ========================"
echo ""

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v docker  >/dev/null 2>&1 || die "docker not found — install Docker Desktop first."
command -v poetry  >/dev/null 2>&1 || die "poetry not found — install with: curl -sSL https://install.python-poetry.org | python3 -"
command -v claude  >/dev/null 2>&1 || die "claude not found — install Claude Code first: https://docs.anthropic.com/en/docs/claude-code"

ok "Prerequisites satisfied (docker, poetry, claude)"

# ── Python dependencies ───────────────────────────────────────────────────────
echo ""
echo "Installing Python dependencies..."
poetry -C "$REPO_DIR" install --no-interaction
ok "Poetry dependencies installed"

# ── Register MCP server with Claude Code ─────────────────────────────────────
echo ""
echo "Registering pentest-agent MCP server..."
# Remove stale registration if it exists (ignore errors)
claude mcp remove --scope user pentest-agent 2>/dev/null || true
claude mcp add --scope user pentest-agent \
    -- poetry -C "$REPO_DIR" run python mcp_server.py
ok "MCP server registered (scope: user)"

# ── Install /pentester slash command ──────────────────────────────────────────
echo ""
echo "Installing /pentester slash command..."
mkdir -p "$HOME/.claude/commands"
cp "$REPO_DIR/skills/pentester.md" "$HOME/.claude/commands/pentester.md"
ok "/pentester command available in all Claude sessions"

# ── Install security analysis skills ─────────────────────────────────────────
echo ""
echo "Installing security analysis skills..."

mkdir -p "$HOME/.claude/skills/analyze-cve"
cp "$REPO_DIR/skills/analyze-cve/SKILL.md" "$HOME/.claude/skills/analyze-cve/SKILL.md"
ok "/analyze-cve skill installed"

mkdir -p "$HOME/.claude/skills/threat-modeling"
cp "$REPO_DIR/skills/threat-modeling/SKILL.md" "$HOME/.claude/skills/threat-modeling/SKILL.md"
ok "/threat-model skill installed"

mkdir -p "$HOME/.claude/skills/aikido-triage"
cp "$REPO_DIR/skills/aikido-triage/SKILL.md" "$HOME/.claude/skills/aikido-triage/SKILL.md"
ok "/aikido-triage skill installed"

mkdir -p "$HOME/.claude/skills/gh-export"
cp "$REPO_DIR/skills/gh-export/SKILL.md" "$HOME/.claude/skills/gh-export/SKILL.md"
ok "/gh-export skill installed"

# ── Auto-approve pentest-agent MCP tools ──────────────────────────────────────
echo ""
echo "Configuring tool permissions (auto-approve pentest-agent tools)..."
python3 - <<'PYEOF'
import json
from pathlib import Path

settings_path = Path.home() / ".claude" / "settings.json"
settings_path.parent.mkdir(exist_ok=True)

try:
    data = json.loads(settings_path.read_text()) if settings_path.exists() else {}
except Exception:
    data = {}

perms = data.setdefault("permissions", {})
allow = perms.setdefault("allow", [])

entry = "mcp__pentest-agent__*"
if entry not in allow:
    allow.append(entry)

settings_path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF
ok "pentest-agent tools will run without approval prompts"

# ── Next steps ────────────────────────────────────────────────────────────────
echo ""
echo "  Done! Optional next steps:"
echo ""
echo "  1. Pre-pull lightweight tool images (recommended, ~2 min):"
echo "     In any Claude Code session, ask Claude to call the pull_images tool."
echo "     Or manually:"
echo "     docker pull instrumentisto/nmap projectdiscovery/naabu projectdiscovery/httpx \\"
echo "                projectdiscovery/nuclei ghcr.io/ffuf/ffuf projectdiscovery/subfinder \\"
echo "                semgrep/semgrep trufflesecurity/trufflehog"
echo ""
echo "  2. Build the Kali image (optional, ~10 min — required for kali_exec):"
echo "     docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
echo ""
echo "  Available commands:"
echo "    /pentester scan https://target.com       — full pentest"
echo "    /analyze-cve lodash 4.17.20 CVE-...      — CVE exploitability analysis"
echo "    /threat-model                             — PASTA threat model"
echo "    /aikido-triage findings.csv /path/to/app — triage Aikido CSV + HTML report"
echo "    /gh-export                               — export findings as GitHub issue blocks"
echo ""
