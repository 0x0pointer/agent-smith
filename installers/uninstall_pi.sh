#!/usr/bin/env bash
# uninstall_pi.sh - remove pentest-agent from the Pi coding agent (https://pi.dev)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Pi's user-level agent directory (honours the same override the CLI uses).
PI_AGENT_DIR="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
PI_SKILLS_DIR="$PI_AGENT_DIR/skills"
PI_PROMPTS_DIR="$PI_AGENT_DIR/prompts"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }

_find_pi() {
    if [[ -n "${PI_BIN:-}" && -x "$PI_BIN" ]]; then
        printf '%s\n' "$PI_BIN"
        return 0
    fi
    if command -v pi >/dev/null 2>&1; then
        command -v pi
        return 0
    fi

    # Pi's managed installer drops a launcher here but does not always add it to
    # the shell PATH (it manages its own Node runtime under ~/.local/share).
    local candidate
    for candidate in \
        "$HOME/.local/bin/pi" \
        "$HOME/.pi/agent/bin/pi"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

echo ""
echo "  pentest-agent uninstaller (Pi)"
echo "  =============================="
echo ""

# Remove the Pi MCP registration. This only changes Pi's MCP config (mcp.json);
# it does not remove the repo, .env, logs, Docker images, or Poetry virtualenv.
if PI_BIN="$(_find_pi)"; then
    "$PI_BIN" mcp remove pentest-agent >/dev/null 2>&1 \
        && ok "pentest-agent MCP server removed from Pi" \
        || warn "pentest-agent MCP server was not registered with Pi (skipping)"
else
    warn "pi CLI not found - skipping MCP removal (edit ~/.pi/agent/mcp.json by hand if needed)"
fi

# Remove the /pentester prompt template the installer added.
if [ -f "$PI_PROMPTS_DIR/pentester.md" ]; then
    rm -f "$PI_PROMPTS_DIR/pentester.md"
    ok "Removed /pentester prompt template"
fi

if [ ! -d "$PI_SKILLS_DIR" ]; then
    warn "$PI_SKILLS_DIR not found - skipping skill removal"
    echo ""
    echo "  Uninstall complete."
    exit 0
fi

_TMP_SKILLS="$(mktemp)"
trap 'rm -f "$_TMP_SKILLS"' EXIT

# Fallback list covers Smith skills installed by older installers even when the
# current skills submodule is incomplete or has local edits.
cat > "$_TMP_SKILLS" <<'EOF'
ad-assessment
ai-redteam
aikido-triage
analyze-cve
android-burp-emulator
android-security
api-security
business-logic
cloud-identity-federation
cloud-security
codebase
colang-gen
compliance
container-k8s-security
credential-audit
email-security
gh-export
ios-security
lateral-movement
masvs-checklist
metasploit
mobile-pentest-plan
network-assess
oauth-security
osint
param-fuzz
pentester
post-exploit
remediate
report
request-cves
reverse-shell
saml-sso
ssl-tls-audit
supply-chain
threat-modeling
web-exploit
EOF

# Also include any current repo skill directories so newly added Smith skills do
# not require a matching uninstaller patch. Mirror the installer's discovery:
# flat skills/<name>/SKILL.md AND nested skills/<domain>/<name>/SKILL.md, plus the
# markdown-only pentester skill.
if [ -d "$REPO_DIR/skills" ]; then
    [ -f "$REPO_DIR/skills/pentester.md" ] && printf '%s\n' "pentester" >> "$_TMP_SKILLS"
    while IFS= read -r _skill_file; do
        [ -e "$_skill_file" ] || continue
        _skill_name="$(basename "$(dirname "$_skill_file")")"
        [ "$_skill_name" = "pentester-opencode" ] && continue
        printf '%s\n' "$_skill_name" >> "$_TMP_SKILLS"
    done < <(find "$REPO_DIR/skills" -mindepth 2 -maxdepth 3 -name SKILL.md 2>/dev/null)
fi

_REMOVED=0
_SKIPPED=0
while IFS= read -r _skill_name; do
    [ -n "$_skill_name" ] || continue
    _skill_dir="$PI_SKILLS_DIR/$_skill_name"
    if [ -d "$_skill_dir" ]; then
        rm -rf "$_skill_dir"
        ok "Removed Pi skill: $_skill_name"
        _REMOVED=$((_REMOVED + 1))
    else
        _SKIPPED=$((_SKIPPED + 1))
    fi
done < <(sort -u "$_TMP_SKILLS")

echo ""
ok "Removed $_REMOVED Pi skill directories"
if [ "$_SKIPPED" -gt 0 ]; then
    warn "$_SKIPPED Smith skill directories were not installed (skipped)"
fi

echo ""
echo "  Uninstall complete."
echo "  Note: Docker images, containers, .env, logs, and the Poetry virtualenv were NOT removed."
echo "  Pi reads config at startup - run /reload or restart Pi to drop the removed tools and skills."
echo "  To clean Docker artifacts manually:"
echo "    docker rm -f pentest-kali pentest-metasploit 2>/dev/null || true"
echo "    docker rmi pentest-agent/kali-mcp pentest-agent/metasploit 2>/dev/null || true"
echo ""
