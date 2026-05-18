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

# ── Start MCP SSE daemon ──────────────────────────────────────────────────────
echo ""
echo "Starting MCP SSE server..."
chmod +x "$REPO_DIR/installers/start-mcp-server.sh"
"$REPO_DIR/installers/start-mcp-server.sh" restart
ok "MCP SSE server running on localhost:7778"

# ── Register MCP server with Claude Code (SSE transport) ──────────────────────
echo ""
echo "Registering pentest-agent MCP server with Claude Code (SSE)..."
claude mcp remove --scope user pentest-agent 2>/dev/null || true
claude mcp add --scope user --transport sse pentest-agent \
    http://127.0.0.1:7778/sse
ok "MCP server registered with Claude Code (scope: user, transport: sse)"

# ── Register MCP server with opencode (SSE transport) ────────────────────────
OPENCODE_CONFIG="$HOME/.config/opencode/config.json"
if [[ -f "$OPENCODE_CONFIG" ]]; then
    echo ""
    echo "Registering pentest-agent MCP server with opencode..."
    jq '.mcp["pentest-agent"] = {"type": "sse", "url": "http://127.0.0.1:7778/sse"}' \
        "$OPENCODE_CONFIG" > "$OPENCODE_CONFIG.tmp" \
        && mv "$OPENCODE_CONFIG.tmp" "$OPENCODE_CONFIG"
    ok "MCP server registered with opencode"
else
    echo "  (opencode config not found at $OPENCODE_CONFIG — skipping opencode registration)"
fi

# ── Install launchd plist for auto-start on login ────────────────────────────
echo ""
echo "Installing launchd plist..."
PLIST_SRC="$REPO_DIR/installers/com.agent-smith.mcp-sse.plist"
PLIST_DST="$HOME/Library/LaunchAgents/com.agent-smith.mcp-sse.plist"
sed "s|REPO_DIR|$REPO_DIR|g" "$PLIST_SRC" > "$PLIST_DST"
launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl load "$PLIST_DST"
ok "launchd plist installed — MCP server auto-starts on login and restarts on crash"

# ── Ask whether to overwrite existing skill files ────────────────────────────
echo ""
_FORCE_SKILLS=false
if ls "$HOME/.claude/skills/"*/SKILL.md "$HOME/.claude/commands/pentester.md" >/dev/null 2>&1; then
    printf "  Existing skill files found in ~/.claude/skills/.\n"
    printf "  Overwrite with fresh copies from the repo? [Y/n]: "
    IFS= read -r _overwrite_answer </dev/tty || true
    echo ""
    if [[ "${_overwrite_answer:-Y}" =~ ^[Yy]$ ]]; then
        _FORCE_SKILLS=true
        ok "Will overwrite existing skill files"
    else
        warn "Keeping existing skill files — skipping skill installation"
    fi
else
    _FORCE_SKILLS=true
fi

# ── Copy helper ───────────────────────────────────────────────────────────────
_cp() {
    local src="$1" dst="$2"
    [[ "$_FORCE_SKILLS" == false ]] && return 0
    rm -f "$dst"
    cp "$src" "$dst"
}

# ── Install /pentester slash command ──────────────────────────────────────────
echo ""
echo "Installing /pentester slash command..."
mkdir -p "$HOME/.claude/commands"
_cp "$REPO_DIR/skills/pentester.md" "$HOME/.claude/commands/pentester.md"
ok "/pentester command available in all Claude sessions"

# ── Install security analysis skills ─────────────────────────────────────────
echo ""
echo "Installing security analysis skills..."

mkdir -p "$HOME/.claude/skills/analyze-cve"
_cp "$REPO_DIR/skills/analyze-cve/SKILL.md" "$HOME/.claude/skills/analyze-cve/SKILL.md"
ok "/analyze-cve skill installed"

mkdir -p "$HOME/.claude/skills/threat-modeling"
_cp "$REPO_DIR/skills/threat-modeling/SKILL.md" "$HOME/.claude/skills/threat-modeling/SKILL.md"
ok "/threat-modeling skill installed"

mkdir -p "$HOME/.claude/skills/aikido-triage"
_cp "$REPO_DIR/skills/aikido-triage/SKILL.md" "$HOME/.claude/skills/aikido-triage/SKILL.md"
ok "/aikido-triage skill installed"

mkdir -p "$HOME/.claude/skills/gh-export"
_cp "$REPO_DIR/skills/gh-export/SKILL.md" "$HOME/.claude/skills/gh-export/SKILL.md"
ok "/gh-export skill installed"

mkdir -p "$HOME/.claude/skills/ai-redteam"
_cp "$REPO_DIR/skills/ai-redteam/SKILL.md" "$HOME/.claude/skills/ai-redteam/SKILL.md"
ok "/ai-redteam skill installed"

mkdir -p "$HOME/.claude/skills/container-k8s-security"
_cp "$REPO_DIR/skills/container-k8s-security/SKILL.md" "$HOME/.claude/skills/container-k8s-security/SKILL.md"
ok "/container-k8s-security skill installed"

mkdir -p "$HOME/.claude/skills/cloud-security"
_cp "$REPO_DIR/skills/cloud-security/SKILL.md" "$HOME/.claude/skills/cloud-security/SKILL.md"
ok "/cloud-security skill installed"

mkdir -p "$HOME/.claude/skills/ad-assessment"
_cp "$REPO_DIR/skills/ad-assessment/SKILL.md" "$HOME/.claude/skills/ad-assessment/SKILL.md"
ok "/ad-assessment skill installed"

mkdir -p "$HOME/.claude/skills/email-security"
_cp "$REPO_DIR/skills/email-security/SKILL.md" "$HOME/.claude/skills/email-security/SKILL.md"
ok "/email-security skill installed"

mkdir -p "$HOME/.claude/skills/metasploit"
_cp "$REPO_DIR/skills/metasploit/SKILL.md" "$HOME/.claude/skills/metasploit/SKILL.md"
ok "/metasploit skill installed"

mkdir -p "$HOME/.claude/skills/reverse-shell"
_cp "$REPO_DIR/skills/reverse-shell/SKILL.md" "$HOME/.claude/skills/reverse-shell/SKILL.md"
ok "/reverse-shell skill installed"

mkdir -p "$HOME/.claude/skills/web-exploit/refs"
_cp "$REPO_DIR/skills/web-exploit/SKILL.md" "$HOME/.claude/skills/web-exploit/SKILL.md"
if [ -d "$REPO_DIR/skills/web-exploit/refs" ]; then
    for _ref_src in "$REPO_DIR/skills/web-exploit/refs/"*; do
        _cp "$_ref_src" "$HOME/.claude/skills/web-exploit/refs/$(basename "$_ref_src")"
    done
fi
ok "/web-exploit skill installed (with lazy-loaded injection refs)"

mkdir -p "$HOME/.claude/skills/api-security"
_cp "$REPO_DIR/skills/api-security/SKILL.md" "$HOME/.claude/skills/api-security/SKILL.md"
ok "/api-security skill installed"

mkdir -p "$HOME/.claude/skills/colang-gen"
_cp "$REPO_DIR/skills/colang-gen/SKILL.md" "$HOME/.claude/skills/colang-gen/SKILL.md"
ok "/colang-gen skill installed"

mkdir -p "$HOME/.claude/skills/codebase"
_cp "$REPO_DIR/skills/codebase/SKILL.md" "$HOME/.claude/skills/codebase/SKILL.md"
ok "/codebase skill installed"

mkdir -p "$HOME/.claude/skills/remediate"
_cp "$REPO_DIR/skills/remediate/SKILL.md" "$HOME/.claude/skills/remediate/SKILL.md"
ok "/remediate skill installed"

mkdir -p "$HOME/.claude/skills/credential-audit"
_cp "$REPO_DIR/skills/credential-audit/SKILL.md" "$HOME/.claude/skills/credential-audit/SKILL.md"
ok "/credential-audit skill installed"

mkdir -p "$HOME/.claude/skills/lateral-movement"
_cp "$REPO_DIR/skills/lateral-movement/SKILL.md" "$HOME/.claude/skills/lateral-movement/SKILL.md"
ok "/lateral-movement skill installed"

mkdir -p "$HOME/.claude/skills/network-assess"
_cp "$REPO_DIR/skills/network-assess/SKILL.md" "$HOME/.claude/skills/network-assess/SKILL.md"
ok "/network-assess skill installed"

mkdir -p "$HOME/.claude/skills/osint"
_cp "$REPO_DIR/skills/osint/SKILL.md" "$HOME/.claude/skills/osint/SKILL.md"
ok "/osint skill installed"

mkdir -p "$HOME/.claude/skills/post-exploit"
_cp "$REPO_DIR/skills/post-exploit/SKILL.md" "$HOME/.claude/skills/post-exploit/SKILL.md"
ok "/post-exploit skill installed"

mkdir -p "$HOME/.claude/skills/ssl-tls-audit"
_cp "$REPO_DIR/skills/ssl-tls-audit/SKILL.md" "$HOME/.claude/skills/ssl-tls-audit/SKILL.md"
ok "/ssl-tls-audit skill installed"

mkdir -p "$HOME/.claude/skills/request-cves"
_cp "$REPO_DIR/skills/request-cves/SKILL.md" "$HOME/.claude/skills/request-cves/SKILL.md"
ok "/request-cves skill installed"

mkdir -p "$HOME/.claude/skills/param-fuzz"
_cp "$REPO_DIR/skills/param-fuzz/SKILL.md" "$HOME/.claude/skills/param-fuzz/SKILL.md"
ok "/param-fuzz skill installed"

mkdir -p "$HOME/.claude/skills/business-logic"
_cp "$REPO_DIR/skills/business-logic/SKILL.md" "$HOME/.claude/skills/business-logic/SKILL.md"
ok "/business-logic skill installed"

mkdir -p "$HOME/.claude/skills/compliance/refs"
_cp "$REPO_DIR/skills/compliance/SKILL.md" "$HOME/.claude/skills/compliance/SKILL.md"
if [ -d "$REPO_DIR/skills/compliance/refs" ]; then
    for _ref_src in "$REPO_DIR/skills/compliance/refs/"*; do
        _cp "$_ref_src" "$HOME/.claude/skills/compliance/refs/$(basename "$_ref_src")"
    done
fi
ok "/compliance skill installed (with ASVS 5.0 CSV ref)"

mkdir -p "$HOME/.claude/skills/report"
_cp "$REPO_DIR/skills/report/SKILL.md" "$HOME/.claude/skills/report/SKILL.md"
ok "/report skill installed"

# ── API keys (AI testing tools) ──────────────────────────────────────────────
echo ""
echo "API keys are stored in $REPO_DIR/.env (mode 600) and loaded automatically."
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

# ── Provider API keys ─────────────────────────────────────────────────────────
echo "  API keys — used by FuzzyAI and PyRIT for AI red-team testing."
echo "  Press Enter to skip any key you don't need right now."
echo ""

_ask_key "OPENAI_API_KEY" \
    "Powers FuzzyAI and PyRIT scoring (openai provider)"
_ask_key "ANTHROPIC_API_KEY" \
    "Powers FuzzyAI and PyRIT scoring (anthropic provider) — API key (sk-ant-...), NOT your Claude.ai login"
_ask_key "AZURE_OPENAI_API_KEY" \
    "Powers FuzzyAI with azure provider"

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
echo "    /api-security https://api.example.com    — OWASP API Top 10 (BOLA, BFLA, mass assignment, ...)"
echo "    /analyze-cve lodash 4.17.20 CVE-...      — CVE exploitability analysis"
echo "    /threat-model                             — PASTA threat model"
echo "    /aikido-triage findings.csv /path/to/app — triage Aikido CSV + HTML report"
echo "    /ai-redteam https://ai-app.com/api/chat   — OWASP LLM Top 10 red-team assessment"
echo "    /colang-gen                              — generate NeMo Guardrails Colang configs"
echo "    /cloud-security my-aws-account provider=aws — cloud security posture assessment"
echo "    /ad-assessment 10.0.0.1 domain=CORP.LOCAL  — Active Directory security audit"
echo "    /email-security example.com              — email SPF/DKIM/DMARC audit"
echo "    /metasploit 10.0.0.5 cve=CVE-2017-0144   — Metasploit exploit validation"
echo "    /gh-export                               — export findings as GitHub issue blocks"
echo "    /compliance /path/to/app                 — full ASVS 5.0 compliance assessment"
echo "    /report target-name                      — generate PDF pentest report from findings"
echo ""
echo "  To rebuild images after adding new skills:"
echo "    docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
echo "    docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
echo ""
