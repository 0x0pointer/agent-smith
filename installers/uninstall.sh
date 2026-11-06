#!/usr/bin/env bash
# uninstall.sh — remove pentest-agent from the current user
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }

echo ""
echo "  pentest-agent uninstaller"
echo "  =========================="
echo ""

# ── Remove MCP registration ───────────────────────────────────────────────────
if command -v claude >/dev/null 2>&1; then
    claude mcp remove --scope user pentest-agent 2>/dev/null \
        && ok "MCP server removed" \
        || warn "pentest-agent MCP server was not registered (skipping)"
else
    warn "claude CLI not found — skipping MCP removal"
fi

# ── Remove the auto-start supervisor (launchd on macOS, systemd on Linux) ────
# install.sh puts the MCP server under a supervisor (KeepAlive=true /
# Restart=always). Left in place it keeps respawning the server on port 7778
# after everything else is removed, so stop and delete it.
PLIST_DST="$HOME/Library/LaunchAgents/com.agent-smith.mcp-sse.plist"
if [ -f "$PLIST_DST" ]; then
    launchctl unload "$PLIST_DST" 2>/dev/null || true
    rm -f "$PLIST_DST"
    ok "launchd plist removed"
fi

SYSTEMD_UNIT="agent-smith-mcp.service"
SYSTEMD_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
if [ -f "$SYSTEMD_UNIT_DIR/$SYSTEMD_UNIT" ]; then
    # `systemctl --user` needs a live user D-Bus session; without one, fall
    # back to removing the files (the enable symlink included) directly.
    if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
        systemctl --user disable --now "$SYSTEMD_UNIT" 2>/dev/null || true
    fi
    rm -f "$SYSTEMD_UNIT_DIR/$SYSTEMD_UNIT" "$SYSTEMD_UNIT_DIR/default.target.wants/$SYSTEMD_UNIT"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl --user daemon-reload 2>/dev/null || true
    fi
    ok "systemd user unit removed ($SYSTEMD_UNIT)"
fi

# ── Remove /pentester slash command ───────────────────────────────────────────
CMD_FILE="$HOME/.claude/commands/pentester.md"
if [ -f "$CMD_FILE" ]; then
    rm "$CMD_FILE"
    ok "/pentester slash command removed"
else
    warn "$CMD_FILE not found (skipping)"
fi

# ── Remove security analysis skills ──────────────────────────────────────────
for skill_dir in "$HOME/.claude/skills/analyze-cve" "$HOME/.claude/skills/threat-modeling" "$HOME/.claude/skills/aikido-triage" "$HOME/.claude/skills/gh-export" "$HOME/.claude/skills/ai-redteam" "$HOME/.claude/skills/colang-gen" "$HOME/.claude/skills/container-k8s-security" "$HOME/.claude/skills/cloud-security" "$HOME/.claude/skills/ad-assessment" "$HOME/.claude/skills/email-security" "$HOME/.claude/skills/metasploit" "$HOME/.claude/skills/reverse-shell" "$HOME/.claude/skills/web-exploit" "$HOME/.claude/skills/api-security" "$HOME/.claude/skills/codebase" "$HOME/.claude/skills/remediate" "$HOME/.claude/skills/credential-audit" "$HOME/.claude/skills/lateral-movement" "$HOME/.claude/skills/network-assess" "$HOME/.claude/skills/osint" "$HOME/.claude/skills/post-exploit" "$HOME/.claude/skills/ssl-tls-audit"; do
    if [ -d "$skill_dir" ]; then
        rm -rf "$skill_dir"
        ok "Removed $(basename "$skill_dir") skill"
    else
        warn "$(basename "$skill_dir") skill not found (skipping)"
    fi
done

# ── Stop Kali container if running ───────────────────────────────────────────
if command -v docker >/dev/null 2>&1; then
    if docker inspect pentest-kali --format='{{.State.Running}}' 2>/dev/null | grep -q true; then
        docker stop pentest-kali 2>/dev/null
        ok "Kali container stopped"
    fi
fi

echo ""
echo "  Uninstall complete."
echo "  Note: Docker images and poetry virtualenv were NOT removed."
echo "  To clean those up manually:"
echo "    docker rmi pentest-agent/kali-mcp instrumentisto/nmap projectdiscovery/naabu \\"
echo "               projectdiscovery/httpx projectdiscovery/nuclei \\"
echo "               projectdiscovery/subfinder semgrep/semgrep trufflesecurity/trufflehog"
echo ""
