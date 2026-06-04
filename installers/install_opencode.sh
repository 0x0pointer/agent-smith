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
echo "Updating skills submodule from upstream..."
if git -C "$REPO_DIR" submodule update --init --recursive --remote skills; then
    ok "Skills submodule updated to $(git -C "$REPO_DIR/skills" rev-parse --short HEAD)"
else
    warn "Could not update skills from upstream — falling back to the pinned submodule commit"
    git -C "$REPO_DIR" submodule update --init --recursive skills
    ok "Skills submodule checked out at pinned commit $(git -C "$REPO_DIR/skills" rev-parse --short HEAD)"
fi

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

# ── Register MCP server + instructions in opencode config ────────────────────
echo ""
echo "Registering pentest-agent MCP server (SSE) in opencode config..."
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

# MCP server entry — remote transport (shared SSE daemon on 127.0.0.1:7778).
# opencode's schema uses "remote" for any HTTP/SSE MCP server; there is no "sse" type.
# timeout defaults to 5_000 ms in opencode if not set — far too short for spider,
# sqlmap, ffuf, kali commands etc. Spider on enterprise SPAs can now run up to
# 2h (see scan_tools._handle_spider), so MCP client timeout is 2.5h to keep a
# safety margin above the longest-running tool.
mcp = data.setdefault("mcp", {})
mcp["pentest-agent"] = {
    "type":    "remote",
    "url":     "http://127.0.0.1:7778/sse",
    "enabled": True,
    "timeout": 9_000_000,
}

# Add CLAUDE.md to global instructions (avoid duplicates)
instructions = data.setdefault("instructions", [])
instructions_entry = str(repo_dir / "CLAUDE.md")
if instructions_entry not in instructions:
    instructions.append(instructions_entry)

config_path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF
ok "MCP server registered in $OPENCODE_CONFIG (transport: remote/SSE)"
ok "CLAUDE.md added to global instructions"

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
if ls "$OPENCODE_COMMANDS_DIR/"*.md >/dev/null 2>&1; then
    printf "  Existing skill files found in %s.\n" "$OPENCODE_COMMANDS_DIR"
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

# ── Install compaction recovery plugin ──────────────────────────────────────
echo ""
echo "Installing compaction recovery plugin..."
mkdir -p "$OPENCODE_PLUGINS_DIR"
rm -f "$OPENCODE_PLUGINS_DIR/opencode-pentest-recovery.mjs"
cp "$REPO_DIR/installers/opencode-pentest-recovery.mjs" \
   "$OPENCODE_PLUGINS_DIR/opencode-pentest-recovery.mjs"
ok "Compaction recovery plugin installed (preserves scan state across context compaction)"

# ── Install slash commands ────────────────────────────────────────────────────
echo ""
echo "Installing slash commands..."
mkdir -p "$OPENCODE_COMMANDS_DIR"

# /pentester — top-level command
if [ -f "$REPO_DIR/skills/pentester-opencode/SKILL.md" ]; then
    _cp "$REPO_DIR/skills/pentester-opencode/SKILL.md" "$OPENCODE_COMMANDS_DIR/pentester.md"
else
    _cp "$REPO_DIR/skills/pentester.md" "$OPENCODE_COMMANDS_DIR/pentester.md"
fi
ok "/pentester command installed"

# Skill commands — each gets its own file
_SKILL_MISSING=()
_SKILL_OK=0
_install_skill() {
    local name="$1"
    local src="$2"
    if [ ! -f "$src" ]; then
        warn "Skill /${name} source not found: $src (skipping)"
        _SKILL_MISSING+=("$name")
        return
    fi
    _cp "$src" "$OPENCODE_COMMANDS_DIR/${name}.md"
    _SKILL_OK=$((_SKILL_OK + 1))
}

for _skill_file in "$REPO_DIR"/skills/*/SKILL.md; do
    [ -e "$_skill_file" ] || continue
    _skill_name="$(basename "$(dirname "$_skill_file")")"

    # /pentester is installed from the OpenCode-specific variant above.
    [ "$_skill_name" = "pentester-opencode" ] && continue

    _install_skill "$_skill_name" "$_skill_file"
done

# Backwards-compatible alias used by older docs and installs.
if [ -f "$REPO_DIR/skills/threat-modeling/SKILL.md" ]; then
    _install_skill "threat-model" "$REPO_DIR/skills/threat-modeling/SKILL.md"
fi

ok "$_SKILL_OK skill commands installed"
if [ ${#_SKILL_MISSING[@]} -gt 0 ]; then
    warn "Missing skills (re-run the installer to fetch the latest skills submodule): ${_SKILL_MISSING[*]}"
fi

# ── Install skill reference files (lazy-loaded support material) ─────────────
echo ""
echo "Installing skill reference files..."
_REF_OK=0
for _refs_src in "$REPO_DIR"/skills/*/refs; do
    [ -d "$_refs_src" ] || continue
    _skill_name="$(basename "$(dirname "$_refs_src")")"
    _refs_dst="$OPENCODE_COMMANDS_DIR/${_skill_name}-refs"

    [[ "$_FORCE_SKILLS" == false ]] && continue

    rm -rf "$_refs_dst"
    mkdir -p "$_refs_dst"
    cp -R "$_refs_src"/. "$_refs_dst"/
    _REF_OK=$((_REF_OK + 1))
done
ok "$_REF_OK skill reference directories installed"

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
echo ""
echo "  To rebuild images after adding new skills:"
echo "    docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
echo "    docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
echo ""
