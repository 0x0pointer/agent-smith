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

# ── Pull skills submodule ────────────────────────────────────────────────────
echo ""
echo "Pulling skills submodule..."
git -C "$REPO_DIR" submodule update --init --recursive
ok "Skills submodule up to date"

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

mkdir -p "$HOME/.claude/skills/container-k8s-security"
cp "$REPO_DIR/skills/container-k8s-security/SKILL.md" "$HOME/.claude/skills/container-k8s-security/SKILL.md"
ok "/container-k8s-security skill installed"

mkdir -p "$HOME/.claude/skills/cloud-security"
cp "$REPO_DIR/skills/cloud-security/SKILL.md" "$HOME/.claude/skills/cloud-security/SKILL.md"
ok "/cloud-security skill installed"

mkdir -p "$HOME/.claude/skills/ad-assessment"
cp "$REPO_DIR/skills/ad-assessment/SKILL.md" "$HOME/.claude/skills/ad-assessment/SKILL.md"
ok "/ad-assessment skill installed"

mkdir -p "$HOME/.claude/skills/email-security"
cp "$REPO_DIR/skills/email-security/SKILL.md" "$HOME/.claude/skills/email-security/SKILL.md"
ok "/email-security skill installed"

mkdir -p "$HOME/.claude/skills/metasploit"
cp "$REPO_DIR/skills/metasploit/SKILL.md" "$HOME/.claude/skills/metasploit/SKILL.md"
ok "/metasploit skill installed"

mkdir -p "$HOME/.claude/skills/reverse-shell"
cp "$REPO_DIR/skills/reverse-shell/SKILL.md" "$HOME/.claude/skills/reverse-shell/SKILL.md"
ok "/reverse-shell skill installed"

mkdir -p "$HOME/.claude/skills/web-exploit"
cp "$REPO_DIR/skills/web-exploit/SKILL.md" "$HOME/.claude/skills/web-exploit/SKILL.md"
ok "/web-exploit skill installed"

mkdir -p "$HOME/.claude/skills/codebase"
cp "$REPO_DIR/skills/codebase/SKILL.md" "$HOME/.claude/skills/codebase/SKILL.md"
ok "/codebase skill installed"

mkdir -p "$HOME/.claude/skills/remediate"
cp "$REPO_DIR/skills/remediate/SKILL.md" "$HOME/.claude/skills/remediate/SKILL.md"
ok "/remediate skill installed"

# ── AI testing API keys (FuzzyAI + PyRIT) ────────────────────────────────────
echo ""
echo "AI testing tools (FuzzyAI + PyRIT) use LLM APIs for attacks and scoring."
echo "Keys are stored in $REPO_DIR/.env (mode 600) and loaded automatically."
echo "Press Enter to skip any key you don't need right now."
echo ""

ENV_FILE="$REPO_DIR/.env"
if [ ! -f "$ENV_FILE" ] && [ -f "$REPO_DIR/.env.example" ]; then
    cp "$REPO_DIR/.env.example" "$ENV_FILE"
else
    touch "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

_ask_key() {
    local key="$1"
    local desc="$2"
    local value=""
    local existing
    existing=$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-) || true
    if [[ -n "$existing" ]]; then
        printf "  %s already set. New value (Enter to keep): " "$key"
    else
        printf "  %s — %s\n  Value (Enter to skip): " "$key" "$desc"
    fi
    # Read from /dev/tty so heredocs in the write path don't steal stdin.
    # -s hides the key as it's typed.
    IFS= read -r -s value </dev/tty || true
    echo ""
    if [[ -n "$value" ]]; then
        # Write the key=value pair using Python to avoid sed injection
        python3 -c "
import pathlib, sys
p = pathlib.Path(sys.argv[1])
lines = [l for l in p.read_text().splitlines() if not l.startswith(sys.argv[2] + '=')]
lines.append(sys.argv[2] + '=' + sys.argv[3])
p.write_text('\n'.join(lines) + '\n')
" "$ENV_FILE" "$key" "$value"
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

# ── Ensure hook scripts are executable ────────────────────────────────────────
chmod +x "$REPO_DIR/.claude/hooks/post-compact.sh" 2>/dev/null || true
ok "Hook scripts are executable"

# ── Next steps ────────────────────────────────────────────────────────────────
echo ""
echo "  Docker images"
echo "  ─────────────"
echo ""

# Lightweight scanner images (pull)
_SCANNER_IMAGES=(
    "instrumentisto/nmap"
    "projectdiscovery/naabu"
    "projectdiscovery/httpx"
    "projectdiscovery/nuclei"
    "ghcr.io/ffuf/ffuf"
    "projectdiscovery/subfinder"
    "semgrep/semgrep"
    "trufflesecurity/trufflehog"
)
printf "  Pull lightweight scanner images? (~2 min) [Y/n]: "
read -r _pull_answer || true
if [[ "${_pull_answer:-Y}" =~ ^[Yy]$ ]]; then
    for img in "${_SCANNER_IMAGES[@]}"; do
        if docker pull "$img" >/dev/null 2>&1; then
            ok "Pulled $img"
        else
            warn "Failed to pull $img (will auto-pull on first use)"
        fi
    done
else
    warn "Scanner image pull skipped — images will auto-pull on first use"
fi

echo ""

# Kali image (build)
printf "  Build Kali image? (~10 min — required for most skills) [Y/n]: "
read -r _kali_answer || true
if [[ "${_kali_answer:-Y}" =~ ^[Yy]$ ]]; then
    echo "  Building pentest-agent/kali-mcp (this may take a while)..."
    if docker build -t pentest-agent/kali-mcp "$REPO_DIR/tools/kali/" 2>&1 | tail -5; then
        ok "Kali image built: pentest-agent/kali-mcp"
    else
        warn "Kali build failed — run manually: docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
    fi
else
    warn "Kali build skipped — run later: docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
fi

echo ""

# Metasploit image (build)
printf "  Build Metasploit image? (~5 min — required for /metasploit skill) [Y/n]: "
read -r _msf_answer || true
if [[ "${_msf_answer:-Y}" =~ ^[Yy]$ ]]; then
    echo "  Building pentest-agent/metasploit..."
    if docker build -t pentest-agent/metasploit "$REPO_DIR/tools/metasploit/" 2>&1 | tail -5; then
        ok "Metasploit image built: pentest-agent/metasploit"
    else
        warn "Metasploit build failed — run manually: docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
    fi
else
    warn "Metasploit build skipped — run later: docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
fi

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "  Install complete!"
echo ""
echo "  Available commands:"
echo "    /pentester scan https://target.com       — full pentest"
echo "    /analyze-cve lodash 4.17.20 CVE-...      — CVE exploitability analysis"
echo "    /threat-model                             — PASTA threat model"
echo "    /aikido-triage findings.csv /path/to/app — triage Aikido CSV + HTML report"
echo "    /ai-redteam https://ai-app.com/api/chat   — OWASP LLM Top 10 red-team assessment"
echo "    /cloud-security my-aws-account provider=aws — cloud security posture assessment"
echo "    /ad-assessment 10.0.0.1 domain=CORP.LOCAL  — Active Directory security audit"
echo "    /email-security example.com              — email SPF/DKIM/DMARC audit"
echo "    /metasploit 10.0.0.5 cve=CVE-2017-0144   — Metasploit exploit validation"
echo "    /gh-export                               — export findings as GitHub issue blocks"
echo ""
echo "  To rebuild images after adding new skills:"
echo "    docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
echo "    docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
echo ""
