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
command -v node    >/dev/null 2>&1 || warn "node not found — Mermaid diagrams will render client-side (install Node.js v18+ for server-side pre-rendering)"

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
    -- poetry -C "$REPO_DIR" run python -m mcp_server
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

mkdir -p "$HOME/.claude/skills/ai-redteam"
cp "$REPO_DIR/skills/ai-redteam/SKILL.md" "$HOME/.claude/skills/ai-redteam/SKILL.md"
ok "/ai-redteam skill installed"

# ── AI testing API keys (FuzzyAI + PyRIT) ────────────────────────────────────
echo ""
echo "AI testing tools (FuzzyAI + PyRIT) use LLM APIs for attacks and scoring."
echo "Keys are stored in $REPO_DIR/.env (mode 600) and loaded automatically."
echo "Press Enter to skip any key you don't need right now."
echo ""

ENV_FILE="$REPO_DIR/.env"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

_ask_key() {
    local key="$1"
    local desc="$2"
    local existing
    existing=$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
    if [[ -n "$existing" ]]; then
        printf "  %s already set. New value (Enter to keep): " "$key"
    else
        printf "  %s — %s\n  Value (Enter to skip): " "$key" "$desc"
    fi
    # Read silently so the key never echoes to the terminal
    IFS= read -r -s value
    echo ""
    if [[ -n "$value" ]]; then
        # Use Python to safely write the key=value pair — avoids sed injection
        # when the value contains shell metacharacters or regex special chars.
        python3 - "$ENV_FILE" "$key" "$value" <<'PYEOF'
import sys, pathlib
env_file, key, value = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
lines = env_file.read_text().splitlines() if env_file.exists() else []
lines = [l for l in lines if not l.startswith(f"{key}=")]
lines.append(f"{key}={value}")
env_file.write_text("\n".join(lines) + "\n")
PYEOF
        ok "$key saved"
    elif [[ -n "$existing" ]]; then
        ok "$key unchanged"
    else
        warn "$key skipped"
    fi
}

_ask_key "OPENAI_API_KEY"      "OpenAI key — FuzzyAI (openai provider) + PyRIT attacker/scorer"
_ask_key "ANTHROPIC_API_KEY"   "Anthropic key — FuzzyAI (anthropic provider)"
_ask_key "AZURE_OPENAI_API_KEY" "Azure OpenAI key — FuzzyAI (azure provider)"

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
echo "                semgrep/semgrep trufflesecurity/trufflehog ghcr.io/cyberark/fuzzyai"
echo ""
echo "  2. Build the Kali image (~10 min — required for kali_exec + run_pyrit):"
echo "     docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
echo "     (PyRIT is installed inside the image; API keys are forwarded at run time)"
echo ""
echo "  Available commands:"
echo "    /pentester scan https://target.com       — full pentest"
echo "    /analyze-cve lodash 4.17.20 CVE-...      — CVE exploitability analysis"
echo "    /threat-model                             — PASTA threat model"
echo "    /aikido-triage findings.csv /path/to/app — triage Aikido CSV + HTML report"
echo "    /ai-redteam https://ai-app.com/api/chat   — OWASP LLM Top 10 red-team assessment"
echo "    /gh-export                               — export findings as GitHub issue blocks"
echo ""
