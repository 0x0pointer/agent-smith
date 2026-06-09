#!/usr/bin/env bash
# install.sh — set up pentest-agent for the current user
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# GUI-launched shells can omit common macOS CLI locations. Keep installer
# prerequisite checks aligned with the MCP launcher runtime.
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/snap/bin:/Applications/Docker.app/Contents/Resources/bin"

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

# ── Disarm any existing launchd plist before restarting the MCP ──────────────
# launchd's plist runs start-mcp-server.sh every 5 s under KeepAlive=true. If a
# previous install left one loaded — especially one pointing at a different
# REPO_DIR — both that script and ours race `lsof -ti tcp:7778 | xargs kill -9`,
# SIGKILLing each other. Unload first; we reload the rewritten plist after the
# MCP is up.
PLIST_DST="$HOME/Library/LaunchAgents/com.agent-smith.mcp-sse.plist"
if [[ -f "$PLIST_DST" ]]; then
    _OLD_REPO="$(awk '/WorkingDirectory/{getline; gsub(/^[[:space:]]*<string>|<\/string>[[:space:]]*$/, ""); print; exit}' "$PLIST_DST")"
    if [[ -n "$_OLD_REPO" && "$_OLD_REPO" != "$REPO_DIR" ]]; then
        warn "Existing launchd plist points at: $_OLD_REPO"
        warn "This install will replace it to point at: $REPO_DIR"
    fi
    launchctl unload "$PLIST_DST" 2>/dev/null || true
fi

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
OPENCODE_CONFIG="$HOME/.config/opencode/opencode.json"
if [[ -f "$OPENCODE_CONFIG" ]]; then
    echo ""
    echo "Registering pentest-agent MCP server with opencode..."
    jq '.mcp["pentest-agent"] = {"type": "remote", "url": "http://127.0.0.1:7778/sse", "enabled": true, "timeout": 9000000}' \
        "$OPENCODE_CONFIG" > "$OPENCODE_CONFIG.tmp" \
        && mv "$OPENCODE_CONFIG.tmp" "$OPENCODE_CONFIG"
    ok "MCP server registered with opencode"
else
    echo "  (opencode config not found at $OPENCODE_CONFIG — skipping opencode registration)"
fi

# ── Install launchd plist for auto-start on login ────────────────────────────
# PLIST_DST was set earlier (pre-disarm step); the unload is a no-op now but
# keeps this section idempotent if someone runs it standalone.
echo ""
echo "Installing launchd plist..."
PLIST_SRC="$REPO_DIR/installers/com.agent-smith.mcp-sse.plist"
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

_SKILL_OK=0
_SKILL_MISSING=()

_install_skill_dir() {
    local name="$1"
    local src="$2"
    local dst="$HOME/.claude/skills/$name"

    if [ ! -f "$src/SKILL.md" ]; then
        warn "Skill /${name} source not found: $src/SKILL.md (skipping)"
        _SKILL_MISSING+=("$name")
        return
    fi

    [[ "$_FORCE_SKILLS" == false ]] && return 0

    rm -rf "$dst"
    mkdir -p "$dst"
    cp -R "$src"/. "$dst"/
    _SKILL_OK=$((_SKILL_OK + 1))
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

mkdir -p "$HOME/.claude/skills"
for _skill_file in "$REPO_DIR"/skills/*/SKILL.md; do
    [ -e "$_skill_file" ] || continue
    _skill_dir="$(dirname "$_skill_file")"
    _skill_name="$(basename "$_skill_dir")"

    # OpenCode has a client-specific variant; Claude uses skills/pentester.md.
    [ "$_skill_name" = "pentester-opencode" ] && continue

    _install_skill_dir "$_skill_name" "$_skill_dir"
done

ok "$_SKILL_OK security analysis skills installed"
if [ ${#_SKILL_MISSING[@]} -gt 0 ]; then
    warn "Missing skills: ${_SKILL_MISSING[*]}"
fi

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

# ── Telegram bridge (optional) ────────────────────────────────────────────────
echo ""
echo "  Telegram bridge (optional) — get HIR / scan-complete alerts on your phone."
echo "  Press Enter twice to skip; the bridge is a no-op when either key is blank."
echo ""
echo "  PREREQUISITE: install the Telegram app (https://telegram.org/apps)."
echo "  Once installed, inside Telegram:"
echo "    1. Open a chat with @BotFather → send /newbot → follow prompts → copy token"
echo "    2. Search for your new bot → open the chat → send /start,"
echo "       then send any text message (e.g. \"hi\") — getUpdates only returns"
echo "       real messages, so /start alone may not surface the chat"
echo "    3. In any browser, visit https://api.telegram.org/bot<TOKEN>/getUpdates"
echo "       → copy the \"chat\":{\"id\": …} value (positive int for DMs, negative for groups/channels)"
echo "       If you get {\"result\":[]}, send another message and refresh"
echo ""

_ask_key "TELEGRAM_BOT_TOKEN" \
    "Bot token from @BotFather (format 123456:ABC-...)"
_ask_key "TELEGRAM_CHAT_ID" \
    "Your Telegram chat ID — receives alerts; only this chat is allowlisted"

# ── Slack bridge (optional) ───────────────────────────────────────────────────
echo ""
echo "  Slack bridge (optional) — same HIR / status alerts in a Slack channel."
echo "  Press Enter to skip. Any combination of Telegram/Slack/Discord can run."
echo ""
echo "  Setup (inside Slack):"
echo "    1. https://api.slack.com/apps → Create New App → From scratch"
echo "    2. Activate Incoming Webhooks → Add New Webhook to Workspace"
echo "    3. Pick the channel that should receive alerts; copy the webhook URL"
echo "       (https://hooks.slack.com/services/T…/B…/…)"
echo ""

_ask_key "SLACK_WEBHOOK_URL" \
    "Slack incoming webhook URL — must start with https://hooks.slack.com/"

# ── Discord bridge (optional) ─────────────────────────────────────────────────
echo ""
echo "  Discord bridge (optional) — same alerts in a Discord channel."
echo "  Press Enter to skip."
echo ""
echo "  Setup (inside Discord):"
echo "    1. Open the channel → Settings → Integrations → Webhooks → New Webhook"
echo "    2. Name it (e.g. \"agent-smith\"), confirm the channel"
echo "    3. Copy the webhook URL (https://discord.com/api/webhooks/<id>/<token>)"
echo ""

_ask_key "DISCORD_WEBHOOK_URL" \
    "Discord webhook URL — must start with https://discord.com/api/webhooks/"

# ── Periodic status updates ───────────────────────────────────────────────────
echo ""
echo "  Periodic status updates send a short scan-summary to every configured"
echo "  notifier sink. Defaults to every 30 min. Set to 0 to disable. The"
echo "  message contains NO target, NO finding titles — only counts."
echo ""

_ask_key "STATUS_UPDATE_INTERVAL_MINUTES" \
    "Status update interval in minutes (default 30; 0 disables)"

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
