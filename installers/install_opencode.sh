#!/usr/bin/env bash
# install_opencode.sh — set up pentest-agent for opencode
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENCODE_CONFIG_DIR="$HOME/.config/opencode"
OPENCODE_CONFIG="$OPENCODE_CONFIG_DIR/opencode.json"
OPENCODE_COMMANDS_DIR="$OPENCODE_CONFIG_DIR/commands"
OPENCODE_PLUGINS_DIR="$OPENCODE_CONFIG_DIR/plugins"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
die()  { echo -e "${RED}✗${NC} $*"; exit 1; }

echo ""
echo "  pentest-agent installer (opencode)"
echo "  ===================================="
echo ""

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v docker   >/dev/null 2>&1 || die "docker not found — install Docker Desktop first."
command -v poetry   >/dev/null 2>&1 || die "poetry not found — install with: curl -sSL https://install.python-poetry.org | python3 -"
command -v opencode >/dev/null 2>&1 || command -v opencode-cli >/dev/null 2>&1 || die "opencode not found — install from: https://opencode.ai"
command -v node    >/dev/null 2>&1 || warn "node not found — Mermaid diagrams will render client-side (install Node.js v18+ for server-side pre-rendering)"

ok "Prerequisites satisfied (docker, poetry, opencode)"

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

# ── Register MCP server + instructions in opencode config ────────────────────
echo ""
echo "Registering pentest-agent MCP server in opencode config..."
mkdir -p "$OPENCODE_CONFIG_DIR"

python3 - <<PYEOF
import json
from pathlib import Path

config_path = Path("$OPENCODE_CONFIG")
repo_dir    = Path("$REPO_DIR")

try:
    data = json.loads(config_path.read_text()) if config_path.exists() else {}
except Exception:
    data = {}

# MCP server entry
mcp = data.setdefault("mcp", {})
mcp["pentest-agent"] = {
    "type":    "local",
    "command": ["poetry", "-C", str(repo_dir), "run", "python", "-m", "mcp_server"],
    "enabled": True,
    "timeout": 30000,
}

# Add CLAUDE.md to global instructions (avoid duplicates)
instructions = data.setdefault("instructions", [])
instructions_entry = str(repo_dir / "CLAUDE.md")
if instructions_entry not in instructions:
    instructions.append(instructions_entry)

config_path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF
ok "MCP server registered in $OPENCODE_CONFIG"
ok "CLAUDE.md added to global instructions"

# ── Install compaction recovery plugin ──────────────────────────────────────
echo ""
echo "Installing compaction recovery plugin..."
mkdir -p "$OPENCODE_PLUGINS_DIR"
cp "$REPO_DIR/installers/opencode-pentest-recovery.mjs" \
   "$OPENCODE_PLUGINS_DIR/opencode-pentest-recovery.mjs"
ok "Compaction recovery plugin installed (preserves scan state across context compaction)"

# ── Install slash commands ────────────────────────────────────────────────────
echo ""
echo "Installing slash commands..."
mkdir -p "$OPENCODE_COMMANDS_DIR"

# /pentester — top-level command
cp "$REPO_DIR/skills/pentester.md" "$OPENCODE_COMMANDS_DIR/pentester.md"
ok "/pentester command installed"

# Skill commands — each gets its own file
_install_skill() {
    local name="$1"
    local src="$2"
    cp "$src" "$OPENCODE_COMMANDS_DIR/${name}.md"
}

_install_skill "analyze-cve"            "$REPO_DIR/skills/analyze-cve/SKILL.md"
_install_skill "threat-model"           "$REPO_DIR/skills/threat-modeling/SKILL.md"
_install_skill "aikido-triage"          "$REPO_DIR/skills/aikido-triage/SKILL.md"
_install_skill "gh-export"              "$REPO_DIR/skills/gh-export/SKILL.md"
_install_skill "ai-redteam"            "$REPO_DIR/skills/ai-redteam/SKILL.md"
_install_skill "container-k8s-security" "$REPO_DIR/skills/container-k8s-security/SKILL.md"
_install_skill "cloud-security"         "$REPO_DIR/skills/cloud-security/SKILL.md"
_install_skill "ad-assessment"          "$REPO_DIR/skills/ad-assessment/SKILL.md"
_install_skill "email-security"         "$REPO_DIR/skills/email-security/SKILL.md"
_install_skill "metasploit"             "$REPO_DIR/skills/metasploit/SKILL.md"
_install_skill "reverse-shell"          "$REPO_DIR/skills/reverse-shell/SKILL.md"
_install_skill "web-exploit"            "$REPO_DIR/skills/web-exploit/SKILL.md"
_install_skill "codebase"               "$REPO_DIR/skills/codebase/SKILL.md"
_install_skill "remediate"              "$REPO_DIR/skills/remediate/SKILL.md"
_install_skill "credential-audit"       "$REPO_DIR/skills/credential-audit/SKILL.md"
_install_skill "lateral-movement"       "$REPO_DIR/skills/lateral-movement/SKILL.md"
_install_skill "network-assess"         "$REPO_DIR/skills/network-assess/SKILL.md"
_install_skill "osint"                  "$REPO_DIR/skills/osint/SKILL.md"
_install_skill "post-exploit"           "$REPO_DIR/skills/post-exploit/SKILL.md"
_install_skill "ssl-tls-audit"          "$REPO_DIR/skills/ssl-tls-audit/SKILL.md"
ok "20 skill commands installed"

# ── Install web-exploit reference files (lazy-loaded per injection type) ─────
echo ""
echo "Installing web-exploit reference files..."
REFS_SRC="$REPO_DIR/skills/web-exploit/refs"
REFS_DST="$OPENCODE_COMMANDS_DIR/web-exploit-refs"
if [ -d "$REFS_SRC" ]; then
    mkdir -p "$REFS_DST"
    cp "$REFS_SRC"/*.md "$REFS_DST/"
    REF_COUNT=$(ls "$REFS_DST"/*.md 2>/dev/null | wc -l | tr -d ' ')
    ok "$REF_COUNT injection reference files installed (lazy-loaded to save context)"
else
    warn "web-exploit/refs/ not found — refs will be read from repo at runtime"
fi

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
    IFS= read -r -s value </dev/tty || true
    echo ""
    if [[ -n "$value" ]]; then
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

_ask_key "OPENAI_API_KEY"       "OpenAI key — FuzzyAI (openai provider) + PyRIT attacker/scorer"
_ask_key "ANTHROPIC_API_KEY"    "Anthropic key — FuzzyAI (anthropic provider)"
_ask_key "AZURE_OPENAI_API_KEY" "Azure OpenAI key — FuzzyAI (azure provider)"

# ── Docker images ─────────────────────────────────────────────────────────────
echo ""
echo "  Docker images"
echo "  ─────────────"
echo ""

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

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "  Install complete!"
echo ""
warn "Tool approvals: opencode has no auto-approve mechanism. Each MCP tool will prompt"
warn "for confirmation on first use in a session — this is expected behaviour."
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
