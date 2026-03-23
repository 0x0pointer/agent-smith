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

# ── Remove /pentester slash command ───────────────────────────────────────────
CMD_FILE="$HOME/.claude/commands/pentester.md"
if [ -f "$CMD_FILE" ]; then
    rm "$CMD_FILE"
    ok "/pentester slash command removed"
else
    warn "$CMD_FILE not found (skipping)"
fi

# ── Remove security analysis skills ──────────────────────────────────────────
for skill_dir in "$HOME/.claude/skills/analyze-cve" "$HOME/.claude/skills/threat-modeling" "$HOME/.claude/skills/aikido-triage" "$HOME/.claude/skills/gh-export" "$HOME/.claude/skills/ai-redteam" "$HOME/.claude/skills/container-k8s-security" "$HOME/.claude/skills/cloud-security" "$HOME/.claude/skills/ad-assessment" "$HOME/.claude/skills/email-security" "$HOME/.claude/skills/metasploit" "$HOME/.claude/skills/reverse-shell" "$HOME/.claude/skills/web-exploit" "$HOME/.claude/skills/codebase" "$HOME/.claude/skills/remediate" "$HOME/.claude/skills/credential-audit" "$HOME/.claude/skills/lateral-movement" "$HOME/.claude/skills/network-assess" "$HOME/.claude/skills/osint" "$HOME/.claude/skills/post-exploit" "$HOME/.claude/skills/ssl-tls-audit"; do
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
echo "               projectdiscovery/httpx projectdiscovery/nuclei ghcr.io/ffuf/ffuf \\"
echo "               projectdiscovery/subfinder semgrep/semgrep trufflesecurity/trufflehog"
echo ""
