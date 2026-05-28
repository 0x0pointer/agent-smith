#!/usr/bin/env bash
# install_codex.sh - set up pentest-agent for OpenAI Codex
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
CODEX_SKILLS_DIR="$CODEX_HOME/skills"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
die()  { echo -e "${RED}[err]${NC} $*"; exit 1; }

echo ""
echo "  pentest-agent installer (Codex)"
echo "  ==============================="
echo ""

# Prerequisites
command -v docker >/dev/null 2>&1 || die "docker not found - install Docker Desktop first."
command -v poetry >/dev/null 2>&1 || die "poetry not found - install with: curl -sSL https://install.python-poetry.org | python3 -"
command -v codex  >/dev/null 2>&1 || die "codex not found - install Codex first: https://developers.openai.com/codex"
command -v node   >/dev/null 2>&1 || warn "node not found - Mermaid diagrams will render client-side (install Node.js v18+ for server-side pre-rendering)"

ok "Prerequisites satisfied (docker, poetry, codex)"

mkdir -p "$CODEX_HOME"

echo ""
echo "Pulling skills submodule..."
git -C "$REPO_DIR" submodule update --init --recursive
ok "Skills submodule up to date"

echo ""
echo "Installing Python dependencies..."
poetry -C "$REPO_DIR" install --no-interaction
ok "Poetry dependencies installed"

# Codex launches this server over stdio. The absolute repo path is intentional:
# the MCP server needs this checkout's .env, logs, tools, and session files.
echo ""
echo "Registering pentest-agent MCP server with Codex (stdio)..."
codex mcp remove pentest-agent >/dev/null 2>&1 || true
codex mcp add pentest-agent -- poetry -C "$REPO_DIR" run python -m mcp_server
ok "MCP server registered with Codex"

# Project instructions and hooks live in the repo. AGENTS.md is read by Codex
# automatically; the hook preserves scan recovery hints after compaction.
chmod +x "$REPO_DIR/.codex/hooks/post-compact.sh" 2>/dev/null || true
ok "Codex project instructions and hooks are ready"

echo ""
_FORCE_SKILLS=false
if find "$CODEX_SKILLS_DIR" -mindepth 2 -maxdepth 2 -name SKILL.md 2>/dev/null | grep -q .; then
    printf "  Existing personal Codex skills found in %s.\n" "$CODEX_SKILLS_DIR"
    printf "  Overwrite pentest-agent skill copies with fresh copies from the repo? [Y/n]: "
    IFS= read -r _overwrite_answer </dev/tty || true
    echo ""
    if [[ "${_overwrite_answer:-Y}" =~ ^[Yy]$ ]]; then
        _FORCE_SKILLS=true
        ok "Will overwrite pentest-agent skill copies"
    else
        warn "Keeping existing Codex skill files - skipping skill installation"
    fi
else
    _FORCE_SKILLS=true
fi

_SKILL_OK=0
_SKILL_MISSING=()

_install_skill_dir() {
    local name="$1"
    local src="$2"
    local dst="$CODEX_SKILLS_DIR/$name"

    if [ ! -f "$src/SKILL.md" ]; then
        warn "Skill ${name} source not found: $src/SKILL.md (skipping)"
        _SKILL_MISSING+=("$name")
        return
    fi

    [[ "$_FORCE_SKILLS" == false ]] && return 0

    rm -rf "$dst"
    mkdir -p "$dst"
    cp -R "$src"/. "$dst"/
    _SKILL_OK=$((_SKILL_OK + 1))
}

_install_markdown_skill() {
    local name="$1"
    local src="$2"
    local dst="$CODEX_SKILLS_DIR/$name"

    if [ ! -f "$src" ]; then
        warn "Skill ${name} source not found: $src (skipping)"
        _SKILL_MISSING+=("$name")
        return
    fi

    [[ "$_FORCE_SKILLS" == false ]] && return 0

    rm -rf "$dst"
    mkdir -p "$dst"
    cp "$src" "$dst/SKILL.md"
    _SKILL_OK=$((_SKILL_OK + 1))
}

echo ""
echo "Installing Codex skills..."
mkdir -p "$CODEX_SKILLS_DIR"

_install_markdown_skill "pentester" "$REPO_DIR/skills/pentester.md"

for _skill_file in "$REPO_DIR"/skills/*/SKILL.md; do
    [ -e "$_skill_file" ] || continue
    _skill_dir="$(dirname "$_skill_file")"
    _skill_name="$(basename "$_skill_dir")"

    # OpenCode has a client-specific variant; Codex uses skills/pentester.md.
    [ "$_skill_name" = "pentester-opencode" ] && continue

    _install_skill_dir "$_skill_name" "$_skill_dir"
done

ok "$_SKILL_OK Codex skills installed"
if [ ${#_SKILL_MISSING[@]} -gt 0 ]; then
    warn "Missing skills (run 'git submodule update --init --recursive' to fetch): ${_SKILL_MISSING[*]}"
fi

echo ""
echo "API keys are stored in $REPO_DIR/.env (mode 600) and loaded automatically."
echo "Press Enter to skip any key you do not need right now."
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
        printf "  %s - %s\n  Value (Enter to skip): " "$key" "$desc"
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

_ask_key "OPENAI_API_KEY"       "OpenAI key - FuzzyAI and PyRIT attacker/scorer"
_ask_key "ANTHROPIC_API_KEY"    "Anthropic key - FuzzyAI anthropic provider"
_ask_key "AZURE_OPENAI_API_KEY" "Azure OpenAI key - FuzzyAI azure provider"

echo ""
echo "  Docker images"
echo "  -------------"
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
    warn "Scanner image pull skipped - images will auto-pull on first use"
fi

echo ""

printf "  Build Kali image? (~10 min - required for most skills) [Y/n]: "
read -r _kali_answer || true
if [[ "${_kali_answer:-Y}" =~ ^[Yy]$ ]]; then
    echo "  Building pentest-agent/kali-mcp (this may take a while)..."
    if docker build -t pentest-agent/kali-mcp "$REPO_DIR/tools/kali/" 2>&1 | tail -5; then
        ok "Kali image built: pentest-agent/kali-mcp"
    else
        warn "Kali build failed - run manually: docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
    fi
else
    warn "Kali build skipped - run later: docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
fi

echo ""

printf "  Build Metasploit image? (~5 min - required for /metasploit skill) [Y/n]: "
read -r _msf_answer || true
if [[ "${_msf_answer:-Y}" =~ ^[Yy]$ ]]; then
    echo "  Building pentest-agent/metasploit..."
    if docker build -t pentest-agent/metasploit "$REPO_DIR/tools/metasploit/" 2>&1 | tail -5; then
        ok "Metasploit image built: pentest-agent/metasploit"
    else
        warn "Metasploit build failed - run manually: docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
    fi
else
    warn "Metasploit build skipped - run later: docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
fi

echo ""
echo "  Install complete!"
echo ""
echo "  Start Codex in this repo and ask for a skill, for example:"
echo "    /pentester scan https://target.com"
echo "    /codebase path=./src"
echo ""
warn "On first open, Codex may ask you to trust this project's AGENTS.md and .codex hooks."
warn "Approve that prompt to enable compaction recovery during long scans."
echo ""
