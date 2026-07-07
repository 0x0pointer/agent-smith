#!/usr/bin/env bash
# install_codex.sh - set up pentest-agent for OpenAI Codex
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
CODEX_SKILLS_DIR="$CODEX_HOME/skills"

# GUI-launched shells can omit common macOS CLI locations. Keep installer
# prerequisite checks aligned with the MCP launcher runtime.
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/snap/bin:/Applications/Docker.app/Contents/Resources/bin"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
die()  { echo -e "${RED}[err]${NC} $*"; exit 1; }

_find_poetry() {
    if command -v poetry >/dev/null 2>&1; then
        command -v poetry
        return 0
    fi

    local macos_poetry="$HOME/Library/Application Support/pypoetry/venv/bin/poetry"
    if [[ -x "$macos_poetry" ]]; then
        printf '%s\n' "$macos_poetry"
        return 0
    fi

    local local_poetry="$HOME/.local/bin/poetry"
    if [[ -x "$local_poetry" ]]; then
        printf '%s\n' "$local_poetry"
        return 0
    fi

    return 1
}

echo ""
echo "  pentest-agent installer (Codex)"
echo "  ==============================="
echo ""

# Prerequisites
command -v docker >/dev/null 2>&1 || die "docker not found - install Docker Desktop first."
POETRY_BIN="$(_find_poetry)" || die "poetry not found - install with: curl -sSL https://install.python-poetry.org | python3 -"
command -v codex  >/dev/null 2>&1 || die "codex not found - install Codex first: https://developers.openai.com/codex"
command -v node   >/dev/null 2>&1 || warn "node not found - Mermaid diagrams will render client-side (install Node.js v18+ for server-side pre-rendering)"

ok "Prerequisites satisfied (docker, poetry, codex)"
ok "Using Poetry at $POETRY_BIN"

mkdir -p "$CODEX_HOME"

echo ""
echo "Updating skills submodule from upstream..."
if git -C "$REPO_DIR" submodule update --init --recursive --remote skills; then
    ok "Skills submodule updated to $(git -C "$REPO_DIR/skills" rev-parse --short HEAD)"
else
    warn "Could not update skills from upstream - falling back to the pinned submodule commit"
    git -C "$REPO_DIR" submodule update --init --recursive skills
    ok "Skills submodule checked out at pinned commit $(git -C "$REPO_DIR/skills" rev-parse --short HEAD)"
fi

echo ""
echo "Installing Python dependencies..."
"$POETRY_BIN" -C "$REPO_DIR" install --no-interaction
ok "Poetry dependencies installed"

chmod +x "$REPO_DIR/installers/run-mcp-server.sh"
"$REPO_DIR/installers/run-mcp-server.sh" --self-test >/dev/null
ok "MCP launcher self-test passed"

# Codex launches this server over stdio. The absolute repo path is intentional:
# the MCP server needs this checkout's .env, logs, tools, and session files.
echo ""
echo "Registering pentest-agent MCP server with Codex (stdio)..."
codex mcp remove pentest-agent >/dev/null 2>&1 || true
codex mcp add pentest-agent -- "$REPO_DIR/installers/run-mcp-server.sh"
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

# Discover flat skills/<name>/SKILL.md AND nested skills/<domain>/<name>/SKILL.md
# (one level of domain nesting, e.g. skills/mobile/android-security/). Install target
# stays flat — nesting exists only in the repo.
while IFS= read -r _skill_file; do
    [ -e "$_skill_file" ] || continue
    _skill_dir="$(dirname "$_skill_file")"
    _skill_name="$(basename "$_skill_dir")"

    # OpenCode has a client-specific variant; Codex uses skills/pentester.md.
    [ "$_skill_name" = "pentester-opencode" ] && continue

    _install_skill_dir "$_skill_name" "$_skill_dir"
done < <(find "$REPO_DIR/skills" -mindepth 2 -maxdepth 3 -name SKILL.md 2>/dev/null)

ok "$_SKILL_OK Codex skills installed"
if [ ${#_SKILL_MISSING[@]} -gt 0 ]; then
    warn "Missing skills (re-run the installer to fetch the latest skills submodule): ${_SKILL_MISSING[*]}"
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
echo "  Telegram bridge (optional) - get HIR / scan-complete alerts on your phone."
echo "  Press Enter twice to skip; the bridge is a no-op when either key is blank."
echo ""
echo "  PREREQUISITE: install the Telegram app (https://telegram.org/apps)."
echo "  Once installed, inside Telegram:"
echo "    1. Open a chat with @BotFather -> send /newbot -> follow prompts -> copy token"
echo "    2. Search for your new bot -> open the chat -> send /start,"
echo "       then send any text message (e.g. \"hi\") - getUpdates only returns"
echo "       real messages, so /start alone may not surface the chat"
echo "    3. In any browser, visit https://api.telegram.org/bot<TOKEN>/getUpdates"
echo "       -> copy the \"chat\":{\"id\": ...} value (positive int for DMs, negative for groups/channels)"
echo "       If you get {\"result\":[]}, send another message and refresh"
echo ""

_ask_key "TELEGRAM_BOT_TOKEN" "Bot token from @BotFather (format 123456:ABC-...)"
_ask_key "TELEGRAM_CHAT_ID"   "Your Telegram chat ID - receives alerts; only this chat is allowlisted"

# ── Slack bridge (optional) ───────────────────────────────────────────────────
echo ""
echo "  Slack bridge (optional) - same HIR / status alerts in a Slack channel."
echo "  Press Enter to skip. Any combination of Telegram/Slack/Discord can run."
echo ""
echo "  Setup (inside Slack):"
echo "    1. https://api.slack.com/apps -> Create New App -> From scratch"
echo "    2. Activate Incoming Webhooks -> Add New Webhook to Workspace"
echo "    3. Pick the channel; copy the webhook URL"
echo "       (https://hooks.slack.com/services/T.../B.../...)"
echo ""

_ask_key "SLACK_WEBHOOK_URL"   "Slack incoming webhook URL - must start with https://hooks.slack.com/"

# ── Discord bridge (optional) ─────────────────────────────────────────────────
echo ""
echo "  Discord bridge (optional) - same alerts in a Discord channel."
echo "  Press Enter to skip."
echo ""
echo "  Setup (inside Discord):"
echo "    1. Open the channel -> Settings -> Integrations -> Webhooks -> New Webhook"
echo "    2. Name it (e.g. \"agent-smith\"), confirm the channel"
echo "    3. Copy the webhook URL (https://discord.com/api/webhooks/<id>/<token>)"
echo ""

_ask_key "DISCORD_WEBHOOK_URL" "Discord webhook URL - must start with https://discord.com/api/webhooks/"

# ── Periodic status updates ───────────────────────────────────────────────────
echo ""
echo "  Periodic status updates push a short scan-summary to every configured"
echo "  notifier sink. Defaults to every 30 min. Set to 0 to disable. The"
echo "  message contains NO target, NO finding titles - only counts."
echo ""

_ask_key "STATUS_UPDATE_INTERVAL_MINUTES" "Status update interval in minutes (default 30; 0 disables)"

# OOB backend for blind-vuln (SSRF/RCE/XXE/OAST-SQLi, DNS exfil) confirmation.
# OOB_MODE=interactsh (default, DNS+HTTP) or http (any logger URL, HTTP-only).
# Blank everything = interactsh public servers (oast.fun).
_ask_key "OOB_MODE"         "OOB backend: interactsh (default) or http (blank = interactsh)"
_ask_key "OOB_SERVER_URL"   "interactsh server URL or http logger base URL (blank = public oast.fun)"
_ask_key "OOB_SERVER_TOKEN" "Auth token for a protected self-hosted interactsh server (blank if none/public)"
_ask_key "OOB_POLL_URL"     "http-mode log read-endpoint, supports {id} (blank = interactsh or manual)"

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

# Kali image (build) - modular: choose which tool domains to bake in.
# core is always installed; each other domain is a --build-arg toggle.
printf "  Build Kali image? (required for most skills) [Y/n]: "
read -r _kali_answer || true
if [[ "${_kali_answer:-Y}" =~ ^[Yy]$ ]]; then
    echo ""
    echo "  Choose Kali tool modules (core is always included). Build-time estimates"
    echo "  are approximate and depend on your network speed:"
    echo ""
    echo "    core   (always)  MCP server, recon: nmap/nuclei/httpx/subfinder, wordlists  ~6 min"
    echo "    web              web/API exploit, fuzzing, injection, JWT/OAuth, SSL, crawl  ~8 min"
    echo "    infra            internal net, AD, credentials, service enum, pivoting       ~5 min"
    echo "    mobile           Android/iOS reversing + Frida/objection dynamic analysis    ~4 min"
    echo "    cloud            AWS/Azure/GCP CLIs, Prowler, ScoutSuite, trivy, kube-bench   ~7 min"
    echo "    ai               LLM red-team: PyRIT, Garak, promptfoo (heaviest: torch)      ~12 min"
    echo ""
    _kali_build_args=()
    _ask_kali_module() {  # args: name  build-arg  default(Y|N)
        local _def="$3" _ans _hint
        [ "$_def" = "Y" ] && _hint="Y/n" || _hint="y/N"
        printf "    Include %-7s module? [%s]: " "$1" "$_hint"
        read -r _ans || true
        _ans="${_ans:-$_def}"
        if [[ "$_ans" =~ ^[Yy]$ ]]; then
            _kali_build_args+=(--build-arg "$2=1")
        else
            _kali_build_args+=(--build-arg "$2=0")
        fi
    }
    _ask_kali_module web    INSTALL_WEB    Y
    _ask_kali_module infra  INSTALL_INFRA  Y
    _ask_kali_module mobile INSTALL_MOBILE N
    _ask_kali_module cloud  INSTALL_CLOUD  N
    _ask_kali_module ai     INSTALL_AI     N
    echo ""
    echo "  Building pentest-agent/kali-mcp (this may take a while)..."
    if docker build "${_kali_build_args[@]}" -t pentest-agent/kali-mcp "$REPO_DIR/tools/kali/" 2>&1 | tail -5; then
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
