#!/usr/bin/env bash
# install.sh — set up pentest-agent for the current user
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# GUI-launched shells can omit common macOS CLI locations. Keep installer
# prerequisite checks aligned with the MCP launcher runtime.
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/snap/bin:/Applications/Docker.app/Contents/Resources/bin"

# ── Platform ─────────────────────────────────────────────────────────────────
# The MCP server is supervised by launchd on macOS and by a systemd *user* unit
# on Linux. Every launchctl / ~/Library/LaunchAgents touch below is gated on
# this: on Linux that directory does not exist, so the ungated plist write
# (`sed ... > "$PLIST_DST"`) failed the redirect and `set -euo pipefail` aborted
# the install before skills were copied (same fix as install_opencode.sh).
case "$(uname -s)" in
    Darwin) OS_KIND="macos" ;;
    Linux)  OS_KIND="linux" ;;
    *)      OS_KIND="other" ;;
esac
SYSTEMD_UNIT="agent-smith-mcp.service"
SYSTEMD_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

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

# ── `smith` control-plane command ─────────────────────────────────────────────
# package-mode=false means Poetry does not install the [tool.poetry.scripts]
# entry, so put a launcher on PATH ourselves.
"$REPO_DIR/installers/install-smith-cli.sh"

# ── Disarm any existing launchd plist before restarting the MCP ──────────────
# launchd's plist runs start-mcp-server.sh every 5 s under KeepAlive=true. If a
# previous install left one loaded — especially one pointing at a different
# REPO_DIR — both that script and ours race `lsof -ti tcp:7778 | xargs kill -9`,
# SIGKILLing each other. Unload first; we reload the rewritten plist after the
# MCP is up.
PLIST_DST="$HOME/Library/LaunchAgents/com.agent-smith.mcp-sse.plist"
if [[ "$OS_KIND" == "macos" && -f "$PLIST_DST" ]]; then
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

# ── Clear a stale dashboard off :7777 ─────────────────────────────────────────
# The dashboard is a detached uvicorn process tracked only by
# $REPO_DIR/logs/dashboard.pid. One left running by an OLDER install (or a
# checkout in another directory) is invisible to that PID file, keeps the port,
# and keeps serving the old code: /healthz answers 200 while new routes 404, and
# `smith start` then reports "unhealthy" because its own dashboard cannot bind.
# Only our own uvicorn is touched; any other process on the port is reported.
_DASHBOARD_PORT=7777
_dashboard_pids() {
    if command -v lsof >/dev/null 2>&1; then
        lsof -tiTCP:"$_DASHBOARD_PORT" -sTCP:LISTEN 2>/dev/null || true
    elif command -v ss >/dev/null 2>&1; then
        ss -ltnpH "sport = :$_DASHBOARD_PORT" 2>/dev/null \
            | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u || true
    fi
}
_reaped_dashboard=0
for _pid in $(_dashboard_pids); do
    _cmd="$(ps -o command= -p "$_pid" 2>/dev/null || true)"
    case "$_cmd" in
        *"core.api_server:app"*)
            kill "$_pid" 2>/dev/null || true
            _reaped_dashboard=1
            ;;
        *)
            warn "Port $_DASHBOARD_PORT is held by a non-agent-smith process (PID $_pid) — the dashboard will not start until it is freed."
            ;;
    esac
done
rm -f "$REPO_DIR/logs/dashboard.pid"
if [[ "$_reaped_dashboard" == 1 ]]; then
    sleep 1
    ok "Stopped the previous dashboard on :$_DASHBOARD_PORT (it restarts from this checkout on next use)"
fi

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

# ── Install the auto-start supervisor (launchd on macOS, systemd on Linux) ───
# PLIST_DST was set earlier (pre-disarm step); the unload is a no-op now but
# keeps this section idempotent if someone runs it standalone.
echo ""
if [[ "$OS_KIND" == "macos" ]]; then
    echo "Installing launchd plist..."
    PLIST_SRC="$REPO_DIR/installers/com.agent-smith.mcp-sse.plist"
    mkdir -p "$(dirname "$PLIST_DST")"
    sed "s|REPO_DIR|$REPO_DIR|g" "$PLIST_SRC" > "$PLIST_DST"
    launchctl unload "$PLIST_DST" 2>/dev/null || true

    # start-mcp-server.sh started a self-managed nohup instance a moment ago (the
    # plist was unloaded then). It still holds port 7778, so launchd's instance
    # would lose the bind and be respawned every 10 s. Hand the port over first —
    # same handover the systemd branch below does.
    _PID_FILE="$REPO_DIR/logs/mcp_sse.pid"
    if [[ -f "$_PID_FILE" ]] && kill -0 "$(cat "$_PID_FILE")" 2>/dev/null; then
        kill "$(cat "$_PID_FILE")" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$_PID_FILE"

    launchctl load "$PLIST_DST"

    # Do not trust `launchctl load`: it succeeds even when the job can never run.
    # The usual cause is a checkout under ~/Desktop, ~/Documents or ~/Downloads —
    # macOS privacy protection (TCC) stops launchd's /bin/bash from reading the
    # script and log there, and the job exits 78 (EX_CONFIG) on every spawn with
    # nothing in the log. Wait for launchd to report a live PID; if it never does,
    # drop the plist and fall back to a self-managed server so the install still
    # ends with a working MCP server.
    _launchd_up=0
    for _i in $(seq 1 30); do
        if launchctl list com.agent-smith.mcp-sse 2>/dev/null | grep -q '"PID"'; then
            _launchd_up=1
            break
        fi
        sleep 0.5
    done
    if [[ "$_launchd_up" == 1 ]]; then
        ok "launchd plist installed — MCP server auto-starts on login and restarts on crash"
    else
        launchctl unload "$PLIST_DST" 2>/dev/null || true
        rm -f "$PLIST_DST"
        warn "launchd could not run the MCP server from $REPO_DIR — auto-start NOT installed."
        case "$REPO_DIR/" in
            "$HOME/Desktop/"*|"$HOME/Documents/"*|"$HOME/Downloads/"*)
                warn "macOS blocks background jobs from reading ~/Desktop, ~/Documents and ~/Downloads."
                warn "Move the checkout elsewhere (e.g. ~/agent-smith) and re-run this installer to get auto-start."
                ;;
            *)
                warn "Inspect it with: launchctl print gui/$(id -u)/com.agent-smith.mcp-sse"
                ;;
        esac
        "$REPO_DIR/installers/start-mcp-server.sh" start
        warn "Running a self-managed MCP server instead. After a reboot or crash, restart it with:"
        warn "  $REPO_DIR/installers/start-mcp-server.sh restart"
    fi
elif [[ "$OS_KIND" == "linux" ]]; then
    echo "Installing systemd user unit..."
    # `systemctl --user` needs a live user D-Bus session. It is absent in some
    # containers, bare `ssh host cmd` invocations and minimal WSL distros — in
    # that case fall back to the self-managed nohup instance that
    # start-mcp-server.sh already launched above, and say so.
    if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
        mkdir -p "$SYSTEMD_UNIT_DIR" "$REPO_DIR/logs"
        sed "s|REPO_DIR|$REPO_DIR|g" \
            "$REPO_DIR/installers/agent-smith-mcp.service" > "$SYSTEMD_UNIT_DIR/$SYSTEMD_UNIT"
        systemctl --user daemon-reload

        # start-mcp-server.sh started a self-managed nohup instance a moment ago
        # (no supervisor was loaded then). It still holds port 7778, so systemd's
        # instance would lose the bind, exit 1 and be respawned every 10 s — the
        # dual-supervisor crash-loop. Hand the port over before enabling.
        _PID_FILE="$REPO_DIR/logs/mcp_sse.pid"
        if [[ -f "$_PID_FILE" ]] && kill -0 "$(cat "$_PID_FILE")" 2>/dev/null; then
            kill "$(cat "$_PID_FILE")" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$_PID_FILE"

        systemctl --user enable --now "$SYSTEMD_UNIT"
        # Survive logout / start at boot on a headless box. Needs polkit or root;
        # best-effort, and the unit still works for the current session without it.
        loginctl enable-linger "$USER" >/dev/null 2>&1 || \
            warn "loginctl enable-linger failed — MCP starts on login, not at boot (fix: sudo loginctl enable-linger $USER)"

        # Readiness poll (curl is not guaranteed on a minimal server image).
        if command -v curl >/dev/null 2>&1; then
            for _i in $(seq 1 20); do
                curl -sf --max-time 1 http://127.0.0.1:7778/sse >/dev/null 2>&1 && break
                sleep 0.5
            done
        else
            sleep 3
        fi
        if systemctl --user is-active --quiet "$SYSTEMD_UNIT"; then
            ok "systemd user unit installed ($SYSTEMD_UNIT) — auto-starts on login and restarts on crash"
        else
            warn "systemd unit installed but not active — check: systemctl --user status $SYSTEMD_UNIT"
            warn "and the server log: $REPO_DIR/logs/mcp_sse.log"
        fi
    else
        warn "No systemd user session available — skipping auto-start unit."
        warn "The MCP server is running as a self-managed process; restart it with:"
        warn "  $REPO_DIR/installers/start-mcp-server.sh restart"
    fi
else
    warn "Unsupported platform '$(uname -s)' for auto-start supervision — skipping."
    warn "The MCP server is running as a self-managed process; restart it with:"
    warn "  $REPO_DIR/installers/start-mcp-server.sh restart"
fi

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
    # Folder copy includes capabilities.yaml (manual-setup prerequisites) when present.
    # NOTE: the MCP server reads the AUTHORITATIVE capabilities.yaml from the repo's
    # skills/<name>/ at runtime (core.capabilities); this installed copy is a mirror.
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
# Discover skills at BOTH skills/<name>/SKILL.md (flat) and skills/<domain>/<name>/SKILL.md
# (one level of domain nesting, e.g. skills/mobile/android-security/). Install target
# stays flat at ~/.claude/skills/<leaf-name>/ — nesting exists only in the repo.
while IFS= read -r _skill_file; do
    [ -e "$_skill_file" ] || continue
    _skill_dir="$(dirname "$_skill_file")"
    _skill_name="$(basename "$_skill_dir")"

    # OpenCode has a client-specific variant; Claude uses skills/pentester.md.
    [ "$_skill_name" = "pentester-opencode" ] && continue

    _install_skill_dir "$_skill_name" "$_skill_dir"
done < <(find "$REPO_DIR/skills" -mindepth 2 -maxdepth 3 -name SKILL.md -not -path '*/skills/construct/*' 2>/dev/null)

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
echo "  API keys — used by Garak for AI red-team scoring."
echo "  Press Enter to skip any key you don't need right now."
echo ""

_ask_key "OPENAI_API_KEY" \
    "Powers Garak scoring (openai provider)"
_ask_key "AITEST_ANTHROPIC_API_KEY" \
    "Powers Garak scoring (anthropic provider) — API key (sk-ant-...), NOT your Claude.ai login. Stored SEPARATELY (AITEST_) so it never bills your Smith agent's model calls."
_ask_key "AZURE_OPENAI_API_KEY" \
    "Powers Garak scoring (azure provider)"

# ── Smith agent model auth: subscription (default) vs API key ─────────────────
_set_env() {
    python3 -c "
import pathlib, sys
p = pathlib.Path(sys.argv[1])
lines = [l for l in p.read_text().splitlines() if not l.startswith(sys.argv[2] + '=')]
lines.append(sys.argv[2] + '=' + sys.argv[3])
p.write_text('\n'.join(lines) + '\n')
" "$ENV_FILE" "$1" "$2"
}
echo ""
echo "  Smith agent model auth — bill its model calls to your Claude SUBSCRIPTION (default) or an API key?"
printf "  Use an API key for the Smith agent (bills credit) instead of your subscription? [y/N]: "
IFS= read -r _use_api </dev/tty || true
echo ""
if [[ "${_use_api:-}" =~ ^[Yy] ]]; then
    _set_env "SMITH_USE_API_KEY" "yes"
    _set_env "SMITH_SPAWN_USE_API_KEY" "1"
    _ask_key "ANTHROPIC_API_KEY" \
        "The Claude API key the Smith agent (interactive + headless) will bill (sk-ant-...)"
    ok "Smith agent will use the API key (SMITH_USE_API_KEY=yes)."
else
    _set_env "SMITH_USE_API_KEY" "no"
    ok "Smith agent will use your Claude subscription (no ANTHROPIC_API_KEY written to .env)."
fi

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

echo ""
echo "── Out-of-band (OOB) interaction backend ─────────────────────────────────────"
echo "  Confirms BLIND vulns (blind SSRF/RCE/XXE/OAST-SQLi, DNS exfil) via callbacks."
echo "  Pluggable backend:"
echo "    OOB_MODE=interactsh (default) — DNS+HTTP via the bundled interactsh-client."
echo "       blank OOB_SERVER_URL = public oast.fun; or your self-hosted interactsh URL."
echo "    OOB_MODE=http — ANY HTTP request logger (e.g. https://oob-logger.example.com,"
echo "       webhook.site). HTTP-only, zero infra. OOB_POLL_URL (optional, supports {id})"
echo "       is the log read-endpoint for automatic polling."
echo "  Press Enter on all to use interactsh public servers."
echo ""

_ask_key "OOB_MODE" \
    "OOB backend: interactsh (default) or http (blank = interactsh)"
_ask_key "OOB_SERVER_URL" \
    "interactsh server URL, or http logger base URL (blank = public oast.fun)"
_ask_key "OOB_SERVER_TOKEN" \
    "Auth token for a protected self-hosted interactsh server (blank if none/public)"
_ask_key "OOB_POLL_URL" \
    "http-mode log read-endpoint, supports {id} (blank = interactsh or manual check)"

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

# ── Control plane (optional) ──────────────────────────────────────────────────
# `smith start` brings up Postgres (docker compose, 127.0.0.1:55432) and the
# dashboard/orchestrator on :7777, which is what lets the dashboard launch and
# track several runs. Plain single-run use through your client does not need it.
echo ""
echo "  Control plane (multi-run dashboard)"
echo "  ───────────────────────────────────"
echo ""
printf "  Start the control plane now? (Postgres on :55432 + dashboard on :7777) [Y/n]: "
read -r _cp_answer || true
if [[ "${_cp_answer:-Y}" =~ ^[Yy]$ ]]; then
    _SMITH_PY="$("$REPO_DIR/installers/run-mcp-server.sh" --print-python 2>/dev/null || true)"
    if [[ -z "$_SMITH_PY" ]]; then
        warn "Could not resolve the project virtualenv — start it later with: smith start"
    elif _cp_out="$(cd "$REPO_DIR" && PYTHONPATH="$REPO_DIR" "$_SMITH_PY" "$REPO_DIR/smith_cli.py" start 2>&1)"; then
        echo "  $_cp_out"
        if [[ "$_cp_out" == *'"status": "started"'* ]]; then
            ok "Control plane running — open the dashboard_url above with #k=<operator_token>"
        else
            warn "Control plane did not come up healthy. Check that port 55432 and 7777 are free, then: smith start"
        fi
    else
        echo "$_cp_out" | tail -5 | sed 's/^/  /'
        warn "smith start failed (is port 55432 already in use by another container?). Retry later with: smith start"
    fi
else
    warn "Control plane not started — run later: smith start   (smith status / smith stop)"
fi

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

# Kali image (build) — modular: choose which tool domains to bake in.
# core is always installed; each other domain is a --build-arg toggle.
# Build a docker image, keeping the FULL build log on disk.
#
# This used to be `docker build ... 2>&1 | tail -5`, which threw the actual error
# away: when the then-pinned `pyrit==0.11.0` became uninstallable (Kali moved to
# Python 3.14, and PyRIT <= 0.13.0 caps Requires-Python at <3.14), pip's
# "No matching distribution found" scrolled past and the operator was left with 5
# lines of Dockerfile context and no cause. Failure detection was never the
# problem — `set -o pipefail` propagated it correctly — visibility was.
#
# Design notes:
#   * FOREGROUND pipeline, not `docker build &`: no detached child to reason about
#     for signal delivery or cleanup, and the exit status comes straight back
#     through the pipeline.
#   * `tee` keeps every line; on a terminal `awk` collapses that to a live
#     one-line step counter, and off a terminal (CI, piped to a file) the full
#     stream is passed through instead.
#   * The awk/cat filter always exits 0, so with `set -o pipefail` the pipeline
#     status is docker's own.
#   * `mktemp` per build: a fixed shared path in /tmp could already be owned by
#     another user, and the redirect failing would print THEIR stale log as this
#     build's error.
_build_progress() {
    if [ -t 1 ]; then
        awk '/^#[0-9]+ \[[ 0-9]*[0-9]+\/[0-9]+\]/ { printf "\r\033[K  %.100s", $0; fflush() }
             END { printf "\r\033[K" }'
    else
        cat
    fi
}

_build_image() {  # $1=label  $2=image tag  $3=context dir  $4..=extra docker build args
    local _label="$1" _tag="$2" _ctx="$3"; shift 3
    local _safe="${_tag//[^a-zA-Z0-9]/-}"
    local _tmp="${TMPDIR:-/tmp}"; _tmp="${_tmp%/}"
    local _log
    # X's must be TRAILING for both BSD and GNU mktemp — a "-XXXXXX.log" template
    # is not expanded and would hand every run the same path.
    _log="$(mktemp "${_tmp}/agent-smith-build-${_safe}-XXXXXX" 2>/dev/null)" \
        || _log="${_tmp}/agent-smith-build-${_safe}.$$.log"
    echo "  Build log: $_log"
    if docker build "$@" -t "$_tag" "$_ctx" 2>&1 | tee "$_log" | _build_progress; then
        ok "$_label image built: $_tag"
        return 0
    fi
    warn "$_label build FAILED. Full log: $_log"
    # Off a terminal the full stream was already echoed above, so don't repeat it.
    # 60 lines, not 30: BuildKit's failure epilogue (the ">>> RUN" frame, the
    # Dockerfile frame, the "failed to solve" line) is ~15 lines on its own, so a
    # short tail can crowd out the failing step's actual output. Guarded on -s so
    # a missing/empty log can't turn this into a second failure.
    if [ -t 1 ] && [ -s "$_log" ]; then
        echo "  ---------------- last 60 log lines ----------------"
        tail -60 "$_log" | sed "s/^/  /"
        echo "  ---------------------------------------------------"
    fi
    # Quoted so the hint stays copy-pasteable when the repo path contains spaces.
    if [ "$#" -gt 0 ]; then
        warn "Retry: docker build $* -t \"$_tag\" \"$_ctx\""
    else
        warn "Retry: docker build -t \"$_tag\" \"$_ctx\""
    fi
    return 1
}

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
    echo "    cloud            AWS/GCP CLIs, Prowler, ScoutSuite, trivy, kube-bench        ~7 min"
    echo "  (LLM red-team 'ai' is no longer a Kali module — Garak is its own image, built below.)"
    echo ""
    _kali_build_args=()
    _ask_kali_module() {  # $1=name  $2=build-arg  $3=default(Y|N)
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
        return 0
    }
    _ask_kali_module web    INSTALL_WEB    Y
    _ask_kali_module infra  INSTALL_INFRA  Y
    _ask_kali_module mobile INSTALL_MOBILE N
    _ask_kali_module cloud  INSTALL_CLOUD  N
    echo ""
    echo "  Building pentest-agent/kali-mcp (this may take a while)..."
    _build_image Kali pentest-agent/kali-mcp "$REPO_DIR/tools/kali/" "${_kali_build_args[@]}" || true
else
    warn "Kali build skipped — run later: docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
fi

echo ""

# Metasploit image (build)
printf "  Build Metasploit image? (~5 min — required for /metasploit skill) [Y/n]: "
read -r _msf_answer || true
if [[ "${_msf_answer:-Y}" =~ ^[Yy]$ ]]; then
    echo "  Building pentest-agent/metasploit..."
    _build_image Metasploit pentest-agent/metasploit "$REPO_DIR/tools/metasploit/" || true
else
    warn "Metasploit build skipped — run later: docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
fi

# Semgrep image (build) — semgrep + curated rule packs baked in, so it runs
# fully OFFLINE under network="none" (issue #178: --config=p/python failed to
# fetch rules with no network and every scan silently read as "clean"). Also
# auto-builds on first scan(tool="semgrep"); pre-build to avoid a wait then.
echo "  Building pentest-agent/semgrep (bakes in offline rule packs)..."
_build_image Semgrep pentest-agent/semgrep "$REPO_DIR/tools/semgrep-image/" \
    || warn "Semgrep build skipped — auto-builds on first scan(tool='semgrep'), or run: docker build -t pentest-agent/semgrep $REPO_DIR/tools/semgrep-image/"

# Garak image (build) — standalone LLM red-team scanner used by /ai-redteam.
# Heavy (torch, ~6-7 GB). Optional here because it ALSO auto-builds on first
# scan(tool="garak"); pre-build to avoid a ~5-min wait on first use.
printf "  Build Garak image now? (~5 min — LLM red-team; else auto-builds on first use) [y/N]: "
read -r _garak_answer || true
if [[ "${_garak_answer:-N}" =~ ^[Yy]$ ]]; then
    echo "  Building pentest-agent/garak..."
    _build_image Garak pentest-agent/garak "$REPO_DIR/tools/garak/" || true
else
    warn "Garak build skipped — auto-builds on first scan(tool='garak'), or run: docker build -t pentest-agent/garak $REPO_DIR/tools/garak/"
fi

# ZAP Client Spider image (pull) — the spider's `deep`/`thorough` discovery uses the
# official ZAP image's Client Spider (issue #184). Large (~3.6 GB, ships Firefox + the
# Client Side Integration add-on). Also auto-pulls on first spider use; pre-pull to
# avoid the wait then.
printf "  Pull the ZAP image now? (~3.6 GB — Client Spider; else auto-pulls on first use) [y/N]: "
read -r _zap_answer || true
if [[ "${_zap_answer:-N}" =~ ^[Yy]$ ]]; then
    echo "  Pulling ghcr.io/zaproxy/zaproxy:stable..."
    docker pull ghcr.io/zaproxy/zaproxy:stable || warn "ZAP pull skipped — auto-pulls on first scan(tool='spider', mode='deep')."
else
    warn "ZAP pull skipped — auto-pulls on first spider deep/thorough run, or: docker pull ghcr.io/zaproxy/zaproxy:stable"
fi

# MobSF needs no build — /android-security & /ios-security use the official MobSF
# image, auto-pulled by tools/mobsf_runner.py on the first scan(tool='mobsf').



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
echo "  Control plane (multi-run dashboard, Postgres-backed):"
echo "    smith start | smith status | smith stop"
echo ""
echo "  To rebuild images after adding new skills:"
echo "    docker build -t pentest-agent/kali-mcp $REPO_DIR/tools/kali/"
echo "    docker build -t pentest-agent/metasploit $REPO_DIR/tools/metasploit/"
echo "    docker build -t pentest-agent/garak $REPO_DIR/tools/garak/   # LLM red-team (else auto-builds)"
echo ""
