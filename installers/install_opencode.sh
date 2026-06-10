#!/usr/bin/env bash
# install_opencode.sh — set up pentest-agent for opencode
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENCODE_CONFIG_DIR="$HOME/.config/opencode"
OPENCODE_CONFIG="$OPENCODE_CONFIG_DIR/opencode.json"
OPENCODE_COMMANDS_DIR="$OPENCODE_CONFIG_DIR/commands"
OPENCODE_PLUGINS_DIR="$OPENCODE_CONFIG_DIR/plugins"
# Agent-callable skills (opencode 1.16.0+). Smith invokes them as
# `skill({name: "web-exploit"})` rather than the human typing the slash
# command. Different layout: folder-per-skill with a SKILL.md inside, not
# a flat .md file. Both locations get populated so human-typed slash
# commands AND agent skill() calls keep working.
OPENCODE_SKILLS_DIR="$OPENCODE_CONFIG_DIR/skills"

# GUI-launched shells can omit common macOS CLI locations. Keep installer
# prerequisite checks aligned with the MCP launcher runtime.
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/snap/bin:/Applications/Docker.app/Contents/Resources/bin"

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

# Permissions — broaden auto-approval so both interactive and dashboard-spawned
# opencode keep working without prompts the operator can't answer.
#
#   doom_loop  — opencode's built-in "repeated similar tool calls" detector.
#                Pentest fuzzing IS legitimate repeated use against the same
#                target (different payloads, headers, methods). Default "ask"
#                prompt would kill `opencode run` (no TTY to answer it).
#   bash       — agent-smith runs many shell commands (kali docker exec,
#                curl, etc.). Default "ask" would prompt on every call.
#   edit       — agent-smith writes findings/PoCs to disk on every confirmed bug.
#   webfetch   — opencode's native webfetch is used during recon.
#
# Note: dashboard-spawned opencode ALSO passes --dangerously-skip-permissions
# (see core/api_server.py:_spawn_smith), which auto-approves any "ask"
# prompts but RESPECTS "deny". To keep a safety backstop without crippling
# the agent, operators can add a `bash` deny pattern for truly destructive
# commands (rm -rf, force-push, etc.) under permission.bash as an object
# with patterns — see https://opencode.ai/docs/permissions/ .
perm = data.setdefault("permission", {})
perm["doom_loop"] = "allow"
for k in ("bash", "edit", "webfetch"):
    perm.setdefault(k, "allow")

# Bump the per-agent iteration cap for `opencode run`. Default is 500 steps,
# which a "thorough" pentest blows past around the 60-70% coverage mark —
# 135 cells × multiple injection tests per cell + finding-filing + qa_replies
# easily totals 1000–1500 turns. 10000 leaves 5× headroom while still
# guaranteeing the run terminates if it ever loops forever.
agent_block = data.setdefault("agent", {})
build_agent = agent_block.setdefault("build", {})
build_agent.setdefault("steps", 10000)

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

# ── Install agent-callable skills (opencode 1.16.0+ skill() tool) ────────────
# The slash commands above are for HUMAN-typed `/web-exploit` input. Smith
# (the AI agent) needs the same skill content discoverable via opencode's
# native `skill({name: "..."})` tool, which only finds folder-shaped skills
# under one of these documented paths:
#   ~/.config/opencode/skills/<name>/SKILL.md     ← canonical opencode
#   ~/.claude/skills/<name>/SKILL.md              ← Claude-compat fallback
#   ~/.agents/skills/<name>/SKILL.md              ← agent-compat fallback
# We populate the canonical opencode location below. Smith can then call
# `skill({name: "web-exploit"})` directly instead of bash + cat-ing the
# file (the workaround pattern in older agent-smith versions).
echo ""
echo "Installing skills for opencode's agent-side skill() tool..."
mkdir -p "$OPENCODE_SKILLS_DIR"
_AGENT_SKILL_OK=0
_install_agent_skill() {
    local name="$1"
    local src="$2"
    [ -f "$src" ] || return
    local dst_dir="$OPENCODE_SKILLS_DIR/$name"
    mkdir -p "$dst_dir"
    _cp "$src" "$dst_dir/SKILL.md"
    # Copy refs/ alongside so the agent doesn't have to chase relative paths
    local refs_src
    refs_src="$(dirname "$src")/refs"
    if [ -d "$refs_src" ]; then
        rm -rf "$dst_dir/refs"
        cp -R "$refs_src" "$dst_dir/refs"
    fi
    _AGENT_SKILL_OK=$((_AGENT_SKILL_OK + 1))
}
# /pentester gets the opencode variant when available
if [ -f "$REPO_DIR/skills/pentester-opencode/SKILL.md" ]; then
    _install_agent_skill "pentester" "$REPO_DIR/skills/pentester-opencode/SKILL.md"
elif [ -f "$REPO_DIR/skills/pentester.md" ]; then
    _install_agent_skill "pentester" "$REPO_DIR/skills/pentester.md"
fi
for _skill_file in "$REPO_DIR"/skills/*/SKILL.md; do
    [ -e "$_skill_file" ] || continue
    _skill_name="$(basename "$(dirname "$_skill_file")")"
    [ "$_skill_name" = "pentester-opencode" ] && continue
    _install_agent_skill "$_skill_name" "$_skill_file"
done
ok "$_AGENT_SKILL_OK agent-callable skills installed in $OPENCODE_SKILLS_DIR"

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

_ask_key "TELEGRAM_BOT_TOKEN" "Bot token from @BotFather (format 123456:ABC-...)"
_ask_key "TELEGRAM_CHAT_ID"   "Your Telegram chat ID — receives alerts; only this chat is allowlisted"

# ── Slack bridge (optional) ───────────────────────────────────────────────────
echo ""
echo "  Slack bridge (optional) — same HIR / status alerts in a Slack channel."
echo "  Press Enter to skip. Any combination of Telegram/Slack/Discord can run."
echo ""
echo "  Setup (inside Slack):"
echo "    1. https://api.slack.com/apps → Create New App → From scratch"
echo "    2. Activate Incoming Webhooks → Add New Webhook to Workspace"
echo "    3. Pick the channel; copy the webhook URL"
echo "       (https://hooks.slack.com/services/T…/B…/…)"
echo ""

_ask_key "SLACK_WEBHOOK_URL"   "Slack incoming webhook URL — must start with https://hooks.slack.com/"

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

_ask_key "DISCORD_WEBHOOK_URL" "Discord webhook URL — must start with https://discord.com/api/webhooks/"

# ── Periodic status updates ───────────────────────────────────────────────────
echo ""
echo "  Periodic status updates push a short scan-summary to every configured"
echo "  notifier sink. Defaults to every 30 min. Set to 0 to disable. The"
echo "  message contains NO target, NO finding titles — only counts."
echo ""

_ask_key "STATUS_UPDATE_INTERVAL_MINUTES" "Status update interval in minutes (default 30; 0 disables)"

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
